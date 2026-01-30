package orgidauthplugin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	RedisAddr           string `json:"redisAddr,omitempty"`
	RedisUsername       string `json:"redisUsername,omitempty"`
	RedisPassword       string `json:"redisPassword,omitempty"`
	OrgHeader           string `json:"orgHeader,omitempty"`
	PoolSize            int    `json:"poolSize,omitempty"`
	MaxConnIdleTime     string `json:"maxConnIdleTime,omitempty"`
	PoolWaitTimeout     string `json:"poolWaitTimeout,omitempty"`
	CacheTTL            string `json:"cacheTTL,omitempty"`
	CacheMaxSize        int    `json:"cacheMaxSize,omitempty"`
	ClusterMode         bool   `json:"clusterMode,omitempty"`
	TLSEnabled          bool   `json:"tlsEnabled,omitempty"`
	TLSCABundle         string `json:"tlsCABundle,omitempty"`
	TLSInsecureSkipVerify bool `json:"tlsInsecureSkipVerify,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		RedisAddr:             "valkey-redis-master.traefik.svc.cluster.local:6379",
		RedisUsername:         "",
		RedisPassword:         "traefik",
		OrgHeader:             "X-Org",
		PoolSize:              10,
		MaxConnIdleTime:       "5m",
		PoolWaitTimeout:       "2s",
		CacheTTL:              "30s",
		CacheMaxSize:          1000,
		ClusterMode:           false,
		TLSEnabled:            false,
		TLSCABundle:           "",
		TLSInsecureSkipVerify: false,
	}
}

// Connection represents a Redis connection
type Connection struct {
	fd       int       // Used for non-TLS connections
	conn     net.Conn  // Used for TLS connections
	lastUsed time.Time
	inUse    bool
	isTLS    bool      // Track connection type
}

// ConnectionPool manages Redis connections
type ConnectionPool struct {
	connections     []*Connection
	mutex           sync.Mutex
	redisAddr       string
	redisUsername   string
	redisPassword   string
	poolSize        int
	maxConnIdleTime time.Duration
	poolWaitTimeout time.Duration
	tlsConfig       *tls.Config
	tlsEnabled      bool
}

// CacheEntry stores cached IP validation results
type CacheEntry struct {
	allowed   bool
	expiresAt time.Time
}

// IPCache caches IP validation results per org
type IPCache struct {
	entries  map[string]*CacheEntry // key: "orgID:clientIP"
	mutex    sync.RWMutex
	maxSize  int
	cacheTTL time.Duration
}

type OrgIDAuth struct {
	next        http.Handler
	orgHeader   string
	name        string
	pool        *ConnectionPool
	cache       *IPCache
	clusterMode bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	// Parse duration strings
	maxConnIdleTime, err := time.ParseDuration(config.MaxConnIdleTime)
	if err != nil {
		maxConnIdleTime = 5 * time.Minute
	}

	poolWaitTimeout, err := time.ParseDuration(config.PoolWaitTimeout)
	if err != nil {
		poolWaitTimeout = 2 * time.Second
	}

	cacheTTL, err := time.ParseDuration(config.CacheTTL)
	if err != nil {
		cacheTTL = 30 * time.Second
	}

	// Initialize TLS configuration if enabled
	var tlsConfig *tls.Config
	if config.TLSEnabled {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: config.TLSInsecureSkipVerify,
		}

		// Load CA bundle if provided
		if config.TLSCABundle != "" {
			caCertPool := x509.NewCertPool()
			if ok := caCertPool.AppendCertsFromPEM([]byte(config.TLSCABundle)); !ok {
				return nil, fmt.Errorf("failed to parse CA bundle")
			}
			tlsConfig.RootCAs = caCertPool
		}
	}

	pool := &ConnectionPool{
		connections:     make([]*Connection, 0, config.PoolSize),
		redisAddr:       config.RedisAddr,
		redisUsername:   config.RedisUsername,
		redisPassword:   config.RedisPassword,
		poolSize:        config.PoolSize,
		maxConnIdleTime: maxConnIdleTime,
		poolWaitTimeout: poolWaitTimeout,
		tlsConfig:       tlsConfig,
		tlsEnabled:      config.TLSEnabled,
	}

	cache := &IPCache{
		entries:  make(map[string]*CacheEntry),
		maxSize:  config.CacheMaxSize,
		cacheTTL: cacheTTL,
	}

	return &OrgIDAuth{
		next:        next,
		orgHeader:   config.OrgHeader,
		name:        name,
		pool:        pool,
		cache:       cache,
		clusterMode: config.ClusterMode,
	}, nil
}

func (o *OrgIDAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := getClientIP(req)

	// Get all X-Org headers sent by JWT middleware (can be multiple headers)
	orgHeaders := req.Header.Values(o.orgHeader)
	var orgIDs []string

	// Process each X-Org header
	for _, orgHeader := range orgHeaders {
		if orgHeader != "" {
			// Handle comma-separated values in single header
			if strings.Contains(orgHeader, ",") {
				for _, orgID := range strings.Split(orgHeader, ",") {
					trimmed := strings.TrimSpace(orgID)
					if trimmed != "" {
						orgIDs = append(orgIDs, trimmed)
					}
				}
			} else {
				// Single org ID
				trimmed := strings.TrimSpace(orgHeader)
				if trimmed != "" {
					orgIDs = append(orgIDs, trimmed)
				}
			}
		}
	}

	if len(orgIDs) == 0 {
		http.Error(rw, "Missing org ID", http.StatusUnauthorized)
		return
	}

	// Check if ANY org allows this IP
	for _, orgID := range orgIDs {
		// Try cache first
		cacheKey := fmt.Sprintf("%s:%s", orgID, clientIP)
		if cached, ok := o.cache.get(cacheKey); ok {
			if cached {
				// Access granted - no logging needed (Traefik logs success in access logs)
				o.next.ServeHTTP(rw, req)
				return
			}
			// Cache says denied, try next org
			continue
		}

		// Cache miss - check with Redis
		allowed, shouldCache := o.isIPAllowedForOrg(orgID, clientIP)

		// Only cache successful queries (not connection failures)
		if shouldCache {
			o.cache.set(cacheKey, allowed, time.Now().Add(o.cache.cacheTTL))
		}

		if allowed {
			// Access granted - no logging needed (Traefik logs success in access logs)
			o.next.ServeHTTP(rw, req)
			return
		}
	}

	log.Printf("[ORGID-AUTH] Access denied for IP %s - no organization allows this IP", clientIP)
	http.Error(rw, "IP not allowed for any organization", http.StatusForbidden)
}

func (o *OrgIDAuth) isIPAllowedForOrg(orgID, clientIP string) (bool, bool) {
	// Get connection from pool
	conn, err := o.pool.getConnection()
	if err != nil {
		log.Printf("[ORGID-AUTH] WARNING: Redis connection pool exhausted for org %s - fail-open: allowing access", orgID)
		return true, false // Fail-open: allow access on connection failures, but don't cache
	}

	// Track if connection failed, so we can remove it from pool
	connFailed := false
	defer func() {
		if connFailed {
			o.pool.removeConnection(conn)
		} else {
			o.pool.returnConnection(conn)
		}
	}()

	// Build the key for this org's allowed IPs set
	key := fmt.Sprintf("uuid:%s:allowed", orgID)

	// Check if the key exists first
	exists := o.redisExists(conn, key)

	// Check if Redis command failed (connection issue)
	if exists < 0 {
		connFailed = true
		log.Printf("[ORGID-AUTH] WARNING: Redis unavailable for org %s - fail-open: allowing access", orgID)
		return true, false // Fail-open: allow access on connection failures, but don't cache
	}

	if exists == 0 {
		// Fail-open policy: allow requests when org ID not found in Redis
		return true, true // Cache this result
	}

	// First try exact IP match (fast path)
	if o.redisSIsMember(conn, key, clientIP) {
		return true, true // IP found in set, allow access
	}

	// If no exact match, check CIDR blocks
	members := o.redisSMembers(conn, key)
	if members == nil {
		// Error fetching members
		connFailed = true
		log.Printf("[ORGID-AUTH] WARNING: Failed to fetch members for org %s - fail-open: allowing access", orgID)
		return true, false
	}

	// Parse client IP
	clientIPParsed := net.ParseIP(clientIP)
	if clientIPParsed == nil {
		log.Printf("[ORGID-AUTH] Invalid client IP format: %s", clientIP)
		return false, true
	}

	// Check if client IP matches any CIDR block
	for _, member := range members {
		if strings.Contains(member, "/") {
			// It's a CIDR block
			_, ipnet, err := net.ParseCIDR(member)
			if err != nil {
				log.Printf("[ORGID-AUTH] Invalid CIDR format in Redis: %s", member)
				continue
			}
			if ipnet.Contains(clientIPParsed) {
				return true, true // IP matches CIDR block
			}
		}
	}

	return false, true // Cache this result (IP not in list or CIDR ranges)
}

// connectToNode creates an authenticated connection to a specific cluster node
func (o *OrgIDAuth) connectToNode(nodeAddr string) (*Connection, error) {
	// If TLS is enabled, use TLS connection
	if o.pool.tlsEnabled {
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", nodeAddr, o.pool.tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("TLS connection failed: %v", err)
		}

		// Perform TLS handshake
		if err := conn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %v", err)
		}

		// Authenticate if needed
		if o.pool.redisPassword != "" {
			var authCmd string
			if o.pool.redisUsername != "" {
				// AUTH username password (Redis 6+)
				authCmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
					len(o.pool.redisUsername), o.pool.redisUsername,
					len(o.pool.redisPassword), o.pool.redisPassword)
			} else {
				// AUTH password (Redis < 6)
				authCmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(o.pool.redisPassword), o.pool.redisPassword)
			}
			if _, err = conn.Write([]byte(authCmd)); err != nil {
				conn.Close()
				return nil, err
			}

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil || !strings.Contains(string(buf[:n]), "+OK") {
				conn.Close()
				return nil, fmt.Errorf("auth failed")
			}
		}

		return &Connection{
			conn:     conn,
			lastUsed: time.Now(),
			inUse:    false,
			isTLS:    true,
		}, nil
	}

	// Plain TCP connection
	host, portStr, err := net.SplitHostPort(nodeAddr)
	if err != nil {
		return nil, fmt.Errorf("parse address: %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: %v", host, err)
	}

	var ip net.IP
	for _, i := range ips {
		if i.To4() != nil {
			ip = i.To4()
			break
		}
	}
	if ip == nil {
		ip = ips[0]
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	sa := &syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip.To4())

	if err := syscall.Connect(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect: %v", err)
	}

	// Authenticate if needed
	if o.pool.redisPassword != "" {
		var authCmd string
		if o.pool.redisUsername != "" {
			// AUTH username password (Redis 6+)
			authCmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
				len(o.pool.redisUsername), o.pool.redisUsername,
				len(o.pool.redisPassword), o.pool.redisPassword)
		} else {
			// AUTH password (Redis < 6)
			authCmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(o.pool.redisPassword), o.pool.redisPassword)
		}
		if _, err = syscall.Write(fd, []byte(authCmd)); err != nil {
			syscall.Close(fd)
			return nil, err
		}

		buf := make([]byte, 1024)
		n, err := syscall.Read(fd, buf)
		if err != nil || !strings.Contains(string(buf[:n]), "+OK") {
			syscall.Close(fd)
			return nil, fmt.Errorf("auth failed")
		}
	}

	return &Connection{
		fd:       fd,
		lastUsed: time.Now(),
		inUse:    false,
		isTLS:    false,
	}, nil
}

// Redis SISMEMBER command with cluster support
func (o *OrgIDAuth) redisSIsMember(conn *Connection, key, member string) bool {
	if !o.clusterMode {
		return o.redisSIsMemberSingleNode(conn, key, member)
	}
	return o.redisSIsMemberCluster(conn, key, member)
}

// Redis SISMEMBER for cluster mode - handles MOVED redirects
func (o *OrgIDAuth) redisSIsMemberCluster(conn *Connection, key, member string) bool {
	// Try the connected node first
	cmd := fmt.Sprintf("*3\r\n$9\r\nSISMEMBER\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
		len(key), key, len(member), member)
	_, err := connWrite(conn, []byte(cmd))
	if err != nil {
		log.Printf("[ORGID-AUTH] Error writing SISMEMBER command: %v", err)
		return false
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := connRead(conn, buf)
	if err != nil {
		log.Printf("[ORGID-AUTH] Error reading SISMEMBER response: %v", err)
		return false
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ORGID-AUTH] Error parsing SISMEMBER response: %v", err)
		return false
	}

	// Check for MOVED redirect
	if strings.HasPrefix(response, "-MOVED") {
		// Extract new node address from MOVED response
		parts := strings.Fields(response)
		if len(parts) >= 3 {
			nodeAddr := parts[2]
			// Connect to the new node and retry
			nodeConn, err := o.connectToNode(nodeAddr)
			if err != nil {
				log.Printf("[ORGID-AUTH] Failed to connect to node %s: %v", nodeAddr, err)
				return false
			}
			defer connClose(nodeConn)
			return o.redisSIsMemberSingleNode(nodeConn, key, member)
		}
	}

	// Parse response (should be ":1" for member exists, ":0" for doesn't exist)
	response = strings.TrimSpace(response)
	return response == ":1"
}

// Redis SISMEMBER for single node
func (o *OrgIDAuth) redisSIsMemberSingleNode(conn *Connection, key, member string) bool {
	cmd := fmt.Sprintf("*3\r\n$9\r\nSISMEMBER\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
		len(key), key, len(member), member)
	_, err := connWrite(conn, []byte(cmd))
	if err != nil {
		log.Printf("[ORGID-AUTH] Error writing SISMEMBER command: %v", err)
		return false
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := connRead(conn, buf)
	if err != nil {
		log.Printf("[ORGID-AUTH] Error reading SISMEMBER response: %v", err)
		return false
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ORGID-AUTH] Error parsing SISMEMBER response: %v", err)
		return false
	}

	// Parse response (should be ":1" for member exists, ":0" for doesn't exist)
	response = strings.TrimSpace(response)
	return response == ":1"
}

// Redis SMEMBERS command with cluster support
func (o *OrgIDAuth) redisSMembers(conn *Connection, key string) []string {
	if !o.clusterMode {
		return o.redisSMembersSingleNode(conn, key)
	}
	return o.redisSMembersCluster(conn, key)
}

// Redis SMEMBERS for single node
func (o *OrgIDAuth) redisSMembersSingleNode(conn *Connection, key string) []string {
	cmd := fmt.Sprintf("*2\r\n$8\r\nSMEMBERS\r\n$%d\r\n%s\r\n", len(key), key)
	_, err := connWrite(conn, []byte(cmd))
	if err != nil {
		log.Printf("[ORGID-AUTH] Error writing SMEMBERS command: %v", err)
		return nil
	}

	// Read response
	buf := make([]byte, 8192) // Larger buffer for multiple members
	n, err := connRead(conn, buf)
	if err != nil {
		log.Printf("[ORGID-AUTH] Error reading SMEMBERS response: %v", err)
		return nil
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ORGID-AUTH] Error parsing SMEMBERS response: %v", err)
		return nil
	}

	// Parse array response
	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "*") {
		return nil
	}

	countStr := response[1:]
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return nil
	}
	if count == 0 {
		return []string{}
	}

	members := make([]string, 0, count)
	for i := 0; i < count; i++ {
		// Read bulk string length line
		lenLine, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		lenLine = strings.TrimSpace(lenLine)
		if !strings.HasPrefix(lenLine, "$") {
			continue
		}

		// Parse length
		lengthStr := lenLine[1:]
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length < 0 {
			continue
		}

		// Read exact number of bytes + \r\n
		memberBytes := make([]byte, length+2)
		_, err = reader.Read(memberBytes)
		if err != nil {
			break
		}

		// Extract member (without \r\n)
		member := string(memberBytes[:length])
		members = append(members, member)
	}

	return members
}

// Redis SMEMBERS for cluster mode - handles MOVED redirects
func (o *OrgIDAuth) redisSMembersCluster(conn *Connection, key string) []string {
	cmd := fmt.Sprintf("*2\r\n$8\r\nSMEMBERS\r\n$%d\r\n%s\r\n", len(key), key)
	_, err := connWrite(conn, []byte(cmd))
	if err != nil {
		log.Printf("[ORGID-AUTH] Error writing SMEMBERS command: %v", err)
		return nil
	}

	// Read response
	buf := make([]byte, 8192)
	n, err := connRead(conn, buf)
	if err != nil {
		log.Printf("[ORGID-AUTH] Error reading SMEMBERS response: %v", err)
		return nil
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ORGID-AUTH] Error parsing SMEMBERS response: %v", err)
		return nil
	}

	// Check for MOVED redirect
	if strings.HasPrefix(response, "-MOVED") {
		// Extract new node address from MOVED response
		parts := strings.Fields(response)
		if len(parts) >= 3 {
			nodeAddr := parts[2]
			// Connect to the new node and retry
			nodeConn, err := o.connectToNode(nodeAddr)
			if err != nil {
				log.Printf("[ORGID-AUTH] Failed to connect to node %s: %v", nodeAddr, err)
				return nil
			}
			defer connClose(nodeConn)
			return o.redisSMembersSingleNode(nodeConn, key)
		}
	}

	// Parse array response
	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "*") {
		return nil
	}

	countStr := response[1:]
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return nil
	}
	if count == 0 {
		return []string{}
	}

	members := make([]string, 0, count)
	for i := 0; i < count; i++ {
		// Read bulk string length line
		lenLine, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		lenLine = strings.TrimSpace(lenLine)
		if !strings.HasPrefix(lenLine, "$") {
			continue
		}

		// Parse length
		lengthStr := lenLine[1:]
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length < 0 {
			continue
		}

		// Read exact number of bytes + \r\n
		memberBytes := make([]byte, length+2)
		_, err = reader.Read(memberBytes)
		if err != nil {
			break
		}

		// Extract member (without \r\n)
		member := string(memberBytes[:length])
		members = append(members, member)
	}

	return members
}

// Redis EXISTS command with cluster support
// Returns: 1 if key exists, 0 if not exists, -1 on error
func (o *OrgIDAuth) redisExists(conn *Connection, key string) int {
	if !o.clusterMode {
		return o.redisExistsSingleNode(conn, key)
	}
	return o.redisExistsCluster(conn, key)
}

// Redis EXISTS for single node
func (o *OrgIDAuth) redisExistsSingleNode(conn *Connection, key string) int {
	cmd := fmt.Sprintf("*2\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n", len(key), key)
	_, err := connWrite(conn, []byte(cmd))
	if err != nil {
		log.Printf("[ORGID-AUTH] Error writing EXISTS command: %v", err)
		return -1
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := connRead(conn, buf)
	if err != nil {
		log.Printf("[ORGID-AUTH] Error reading EXISTS response: %v", err)
		return -1
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ORGID-AUTH] Error parsing EXISTS response: %v", err)
		return -1
	}

	// Parse response (should be ":1" for exists, ":0" for doesn't exist)
	response = strings.TrimSpace(response)
	if response == ":1" {
		return 1
	} else if response == ":0" {
		return 0
	}

	return -1 // Parse error
}

// Redis EXISTS for cluster mode - handles MOVED redirects
func (o *OrgIDAuth) redisExistsCluster(conn *Connection, key string) int {
	cmd := fmt.Sprintf("*2\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n", len(key), key)
	_, err := connWrite(conn, []byte(cmd))
	if err != nil {
		log.Printf("[ORGID-AUTH] Error writing EXISTS command: %v", err)
		return -1
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := connRead(conn, buf)
	if err != nil {
		log.Printf("[ORGID-AUTH] Error reading EXISTS response: %v", err)
		return -1
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ORGID-AUTH] Error parsing EXISTS response: %v", err)
		return -1
	}

	// Check for MOVED redirect
	if strings.HasPrefix(response, "-MOVED") {
		// Extract new node address from MOVED response
		parts := strings.Fields(response)
		if len(parts) >= 3 {
			nodeAddr := parts[2]
			// Connect to the new node and retry
			nodeConn, err := o.connectToNode(nodeAddr)
			if err != nil {
				log.Printf("[ORGID-AUTH] Failed to connect to node %s: %v", nodeAddr, err)
				return -1
			}
			defer connClose(nodeConn)
			return o.redisExistsSingleNode(nodeConn, key)
		}
	}

	// Parse response (should be ":1" for exists, ":0" for doesn't exist)
	response = strings.TrimSpace(response)
	if response == ":1" {
		return 1
	} else if response == ":0" {
		return 0
	}

	return -1 // Parse error
}

// getClientIP implements Traefik's IP detection logic
func getClientIP(req *http.Request) string {
	// Try X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" && isValidIP(clientIP) {
				return clientIP
			}
		}
	}

	// Try X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" && isValidIP(xri) {
		return xri
	}

	// Fall back to RemoteAddr
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// get retrieves a cached result if valid
func (c *IPCache) get(key string) (bool, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return false, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return false, false
	}

	return entry.allowed, true
}

// set stores a validation result in cache
func (c *IPCache) set(key string, allowed bool, expiresAt time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Simple eviction: if cache is full, clear oldest 10%
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &CacheEntry{
		allowed:   allowed,
		expiresAt: expiresAt,
	}
}

// evictOldest removes expired entries and oldest 10% if needed
func (c *IPCache) evictOldest() {
	now := time.Now()
	toDelete := make([]string, 0)

	// First, remove all expired entries
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		delete(c.entries, key)
	}

	// If still over capacity, remove 10% of entries
	if len(c.entries) >= c.maxSize {
		count := len(c.entries) / 10
		if count < 1 {
			count = 1
		}
		removed := 0
		for key := range c.entries {
			delete(c.entries, key)
			removed++
			if removed >= count {
				break
			}
		}
		log.Printf("[ORGID-AUTH] Cache evicted %d entries (size: %d/%d)", removed, len(c.entries), c.maxSize)
	}
}

// getConnection gets a connection from the pool
func (p *ConnectionPool) getConnection() (*Connection, error) {
	startTime := time.Now()

	for {
		p.mutex.Lock()

		// Find available connection and check if stale
		for i, conn := range p.connections {
			if !conn.inUse {
				// Check if connection is stale
				if time.Since(conn.lastUsed) > p.maxConnIdleTime {
					connType := "plain"
					if conn.isTLS {
						connType = "TLS"
					}
					log.Printf("[ORGID-AUTH] Removing stale %s connection (idle for %v)", connType, time.Since(conn.lastUsed))
					connClose(conn)
					// Remove stale connection
					p.connections = append(p.connections[:i], p.connections[i+1:]...)
					continue
				}

				// Connection is good, mark as in use
				conn.inUse = true
				conn.lastUsed = time.Now()
				p.mutex.Unlock()
				return conn, nil
			}
		}

		// Create new connection if pool not full
		if len(p.connections) < p.poolSize {
			conn, err := p.createConnection()
			if err != nil {
				p.mutex.Unlock()
				return nil, err
			}
			conn.inUse = true
			p.connections = append(p.connections, conn)
			p.mutex.Unlock()
			return conn, nil
		}

		p.mutex.Unlock()

		// Pool is exhausted, check if we should wait
		if time.Since(startTime) >= p.poolWaitTimeout {
			return nil, fmt.Errorf("connection pool exhausted after %v wait", p.poolWaitTimeout)
		}

		// Wait a bit before retrying
		time.Sleep(10 * time.Millisecond)
	}
}

// returnConnection returns a connection to the pool
func (p *ConnectionPool) returnConnection(conn *Connection) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	conn.inUse = false
	conn.lastUsed = time.Now()
}

// removeConnection removes and closes a failed connection from the pool
func (p *ConnectionPool) removeConnection(conn *Connection) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Close the connection
	if err := connClose(conn); err == nil {
		if conn.isTLS {
			log.Printf("[ORGID-AUTH] Closed failed TLS connection")
		} else {
			log.Printf("[ORGID-AUTH] Closed failed connection fd=%d", conn.fd)
		}
	}

	// Remove from pool
	for i, c := range p.connections {
		if c == conn {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			break
		}
	}
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, conn := range p.connections {
		if err := connClose(conn); err == nil {
			connType := "plain"
			if conn.isTLS {
				connType = "TLS"
			}
			log.Printf("[ORGID-AUTH] Closed %s connection during shutdown", connType)
		}
	}
	p.connections = nil
}

// createConnection creates a new Redis connection
func (p *ConnectionPool) createConnection() (*Connection, error) {
	// If TLS is enabled, use TLS connection
	if p.tlsEnabled {
		return p.createTLSConnection()
	}
	return p.createPlainConnection()
}

// createTLSConnection creates a new TLS Redis connection
func (p *ConnectionPool) createTLSConnection() (*Connection, error) {
	// Use tls.Dial to establish TLS connection
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", p.redisAddr, p.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %v", err)
	}

	// Perform TLS handshake
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	// Authenticate if password is set
	if p.redisPassword != "" {
		var authCmd string
		if p.redisUsername != "" {
			// AUTH username password (Redis 6+)
			authCmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
				len(p.redisUsername), p.redisUsername,
				len(p.redisPassword), p.redisPassword)
		} else {
			// AUTH password (Redis < 6)
			authCmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(p.redisPassword), p.redisPassword)
		}
		_, err = conn.Write([]byte(authCmd))
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send auth command: %v", err)
		}

		// Read auth response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read auth response: %v", err)
		}

		if !strings.Contains(string(buf[:n]), "+OK") {
			conn.Close()
			return nil, fmt.Errorf("authentication failed")
		}
	}

	return &Connection{
		conn:     conn,
		lastUsed: time.Now(),
		inUse:    false,
		isTLS:    true,
	}, nil
}

// createPlainConnection creates a new plain (non-TLS) Redis connection
func (p *ConnectionPool) createPlainConnection() (*Connection, error) {
	// Parse host and port
	host, portStr, err := net.SplitHostPort(p.redisAddr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	// Resolve hostname to IP
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for host %s", host)
	}

	// Use the first IP (prefer IPv4)
	var ip net.IP
	for _, i := range ips {
		if i.To4() != nil {
			ip = i.To4()
			break
		}
	}
	if ip == nil {
		ip = ips[0]
	}

	// Create socket using syscall
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %v", err)
	}

	// Set socket to non-blocking for timeout support
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Create sockaddr
	sa := &syscall.SockaddrInet4{
		Port: port,
	}
	copy(sa.Addr[:], ip.To4())

	// Connect (will return EINPROGRESS for non-blocking socket)
	err = syscall.Connect(fd, sa)
	if err != nil && err != syscall.EINPROGRESS {
		syscall.Close(fd)
		return nil, err
	}

	// Wait for connection with timeout using select
	if err == syscall.EINPROGRESS {
		fdSet := &syscall.FdSet{}
		fdSet.Bits[fd/64] |= 1 << (uint(fd) % 64)

		if err := selectWithTimeout(fd, fdSet, 5*time.Second); err != nil {
			syscall.Close(fd)
			return nil, err
		}

		// Check if the socket is writable (connection succeeded or failed)
		if (fdSet.Bits[fd/64] & (1 << (uint(fd) % 64))) == 0 {
			syscall.Close(fd)
			return nil, fmt.Errorf("connection timeout")
		}

		// Check if connection succeeded
		soErr, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil {
			syscall.Close(fd)
			return nil, err
		}
		if soErr != 0 {
			syscall.Close(fd)
			return nil, syscall.Errno(soErr)
		}
	}

	// Set socket back to blocking mode
	if err := syscall.SetNonblock(fd, false); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Enable TCP keepalive for connection health monitoring
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
		log.Printf("[ORGID-AUTH] Warning: failed to set TCP keepalive: %v", err)
		// Don't fail connection creation for this
	}

	// Authenticate if password is set
	if p.redisPassword != "" {
		var authCmd string
		if p.redisUsername != "" {
			// AUTH username password (Redis 6+)
			authCmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
				len(p.redisUsername), p.redisUsername,
				len(p.redisPassword), p.redisPassword)
		} else {
			// AUTH password (Redis < 6)
			authCmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(p.redisPassword), p.redisPassword)
		}
		_, err = syscall.Write(fd, []byte(authCmd))
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to send auth command: %v", err)
		}

		// Read auth response
		buf := make([]byte, 1024)
		n, err := syscall.Read(fd, buf)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to read auth response: %v", err)
		}

		if !strings.Contains(string(buf[:n]), "+OK") {
			syscall.Close(fd)
			return nil, fmt.Errorf("authentication failed")
		}
	}

	return &Connection{
		fd:       fd,
		lastUsed: time.Now(),
		inUse:    false,
		isTLS:    false,
	}, nil
}

// connRead reads from a connection (TLS or non-TLS)
func connRead(conn *Connection, buf []byte) (int, error) {
	if conn.isTLS {
		return conn.conn.Read(buf)
	}
	return syscall.Read(conn.fd, buf)
}

// connWrite writes to a connection (TLS or non-TLS)
func connWrite(conn *Connection, data []byte) (int, error) {
	if conn.isTLS {
		return conn.conn.Write(data)
	}
	return syscall.Write(conn.fd, data)
}

// connClose closes a connection (TLS or non-TLS)
func connClose(conn *Connection) error {
	if conn.isTLS {
		if conn.conn != nil {
			return conn.conn.Close()
		}
		return nil
	}
	if conn.fd > 0 {
		return syscall.Close(conn.fd)
	}
	return nil
}
