package orgidauthplugin

import (
	"bufio"
	"bytes"
	"context"
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
	RedisAddr        string `json:"redisAddr,omitempty"`
	RedisPassword    string `json:"redisPassword,omitempty"`
	OrgHeader        string `json:"orgHeader,omitempty"`
	PoolSize         int    `json:"poolSize,omitempty"`
	MaxConnIdleTime  string `json:"maxConnIdleTime,omitempty"`
	PoolWaitTimeout  string `json:"poolWaitTimeout,omitempty"`
	CacheTTL         string `json:"cacheTTL,omitempty"`
	CacheMaxSize     int    `json:"cacheMaxSize,omitempty"`
	ClusterMode      bool   `json:"clusterMode,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		RedisAddr:       "valkey-redis-master.traefik.svc.cluster.local:6379",
		RedisPassword:   "traefik",
		OrgHeader:       "X-Org",
		PoolSize:        10,
		MaxConnIdleTime: "5m",
		PoolWaitTimeout: "2s",
		CacheTTL:        "30s",
		CacheMaxSize:    1000,
		ClusterMode:     false,
	}
}

// Connection represents a Redis connection
type Connection struct {
	fd       int
	lastUsed time.Time
	inUse    bool
}

// ConnectionPool manages Redis connections
type ConnectionPool struct {
	connections     []*Connection
	mutex           sync.Mutex
	redisAddr       string
	redisPassword   string
	poolSize        int
	maxConnIdleTime time.Duration
	poolWaitTimeout time.Duration
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

	pool := &ConnectionPool{
		connections:     make([]*Connection, 0, config.PoolSize),
		redisAddr:       config.RedisAddr,
		redisPassword:   config.RedisPassword,
		poolSize:        config.PoolSize,
		maxConnIdleTime: maxConnIdleTime,
		poolWaitTimeout: poolWaitTimeout,
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

	// Get keys matching pattern for UUID organizations: uuid:{orgID}:*
	pattern := fmt.Sprintf("uuid:%s:*", orgID)
	keys := o.redisKeys(conn.fd, pattern)

	// Check if Redis command failed (connection issue)
	if keys == nil && pattern != "" {
		connFailed = true
		log.Printf("[ORGID-AUTH] WARNING: Redis unavailable for org %s - fail-open: allowing access", orgID)
		return true, false // Fail-open: allow access on connection failures, but don't cache
	}

	if len(keys) == 0 {
		// Fail-open policy: allow requests when org ID not found in Valkey
		return true, true // Cache this result
	}

	// Check each key for matching IPs
	for _, key := range keys {
		ipsStr := o.redisHGet(conn.fd, key, "ips")

		// Note: Empty string is valid (field doesn't exist), but we can't distinguish
		// from connection failure without changing redisHGet signature
		if ipsStr == "" {
			continue
		}

		// Parse IPs from string format [ip1 ip2 ip3] or clean format
		ipsStr = strings.Trim(ipsStr, "[]")
		ipsStr = strings.TrimSpace(ipsStr)

		// Split by space and clean each IP
		ips := strings.Fields(ipsStr)

		for _, ip := range ips {
			if ip == clientIP {
				return true, true // Cache this result
			}
		}
	}

	return false, true // Cache this result (IP not in list)
}

// Redis KEYS command with cluster support
func (o *OrgIDAuth) redisKeys(fd int, pattern string) []string {
	if !o.clusterMode {
		// Single node mode - use current implementation
		return o.redisKeysSingleNode(fd, pattern)
	}

	// Cluster mode - query all nodes
	return o.redisKeysCluster(fd, pattern)
}

// Redis KEYS command for single node
func (o *OrgIDAuth) redisKeysSingleNode(fd int, pattern string) []string {
	cmd := fmt.Sprintf("*2\r\n$4\r\nKEYS\r\n$%d\r\n%s\r\n", len(pattern), pattern)
	_, err := syscall.Write(fd, []byte(cmd))
	if err != nil {
		return nil
	}

	// Read response into buffer
	buf := make([]byte, 8192)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		return nil
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
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
		return nil // Parse error = connection issue
	}
	if count == 0 {
		return []string{} // Empty result = org doesn't exist (valid response)
	}

	keys := make([]string, 0, count)
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
		keyBytes := make([]byte, length+2)
		_, err = reader.Read(keyBytes)
		if err != nil {
			break
		}

		// Extract key (without \r\n)
		key := string(keyBytes[:length])
		keys = append(keys, key)
	}

	return keys
}

// Redis KEYS command for cluster mode - queries all nodes
func (o *OrgIDAuth) redisKeysCluster(fd int, pattern string) []string {
	// Get all cluster nodes
	nodes := o.getClusterNodes(fd)
	if len(nodes) == 0 {
		log.Printf("[ORGID-AUTH] WARNING: Could not get cluster nodes, falling back to single node")
		return o.redisKeysSingleNode(fd, pattern)
	}

	log.Printf("[ORGID-AUTH] Cluster mode: querying %d nodes for pattern %s", len(nodes), pattern)

	// Query each node and aggregate results
	allKeys := make(map[string]bool)
	for _, nodeAddr := range nodes {
		nodeKeys := o.queryNodeForKeys(nodeAddr, pattern)
		for _, key := range nodeKeys {
			allKeys[key] = true
		}
	}

	// Convert map to slice
	keys := make([]string, 0, len(allKeys))
	for key := range allKeys {
		keys = append(keys, key)
	}

	log.Printf("[ORGID-AUTH] Cluster mode: found %d unique keys across all nodes", len(keys))
	return keys
}

// Get all cluster node addresses
func (o *OrgIDAuth) getClusterNodes(fd int) []string {
	cmd := "*2\r\n$7\r\nCLUSTER\r\n$5\r\nNODES\r\n"
	_, err := syscall.Write(fd, []byte(cmd))
	if err != nil {
		return nil
	}

	// Read response
	buf := make([]byte, 16384)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		return nil
	}

	response := string(buf[:n])

	// Parse CLUSTER NODES response
	// Format: $<length>\r\n<data>\r\n
	if !strings.HasPrefix(response, "$") {
		return nil
	}

	lines := strings.Split(response, "\r\n")
	if len(lines) < 2 {
		return nil
	}

	// Skip first line ($length) and last line (empty)
	nodesData := lines[1]

	// Parse each node line
	// Format: <id> <ip:port@cport> <flags> <master> <ping-sent> <pong-recv> <config-epoch> <link-state> <slot> <slot> ... <slot>
	nodeLines := strings.Split(nodesData, "\n")
	var nodes []string

	for _, line := range nodeLines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		// Extract IP:port from field[1] (format: ip:port@cport)
		addrParts := strings.Split(fields[1], "@")
		if len(addrParts) > 0 {
			addr := addrParts[0]
			// Only include master nodes or standalone nodes
			if !strings.Contains(fields[2], "slave") {
				nodes = append(nodes, addr)
			}
		}
	}

	return nodes
}

// connectToNode creates an authenticated connection to a specific cluster node
func (o *OrgIDAuth) connectToNode(nodeAddr string) (int, error) {
	host, portStr, err := net.SplitHostPort(nodeAddr)
	if err != nil {
		return -1, fmt.Errorf("parse address: %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return -1, err
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return -1, fmt.Errorf("resolve %s: %v", host, err)
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
		return -1, err
	}

	sa := &syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip.To4())

	if err := syscall.Connect(fd, sa); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("connect: %v", err)
	}

	// Authenticate if needed
	if o.pool.redisPassword != "" {
		authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(o.pool.redisPassword), o.pool.redisPassword)
		if _, err = syscall.Write(fd, []byte(authCmd)); err != nil {
			syscall.Close(fd)
			return -1, err
		}

		buf := make([]byte, 1024)
		n, err := syscall.Read(fd, buf)
		if err != nil || !strings.Contains(string(buf[:n]), "+OK") {
			syscall.Close(fd)
			return -1, fmt.Errorf("auth failed")
		}
	}

	return fd, nil
}

// Query a specific node for keys matching pattern
func (o *OrgIDAuth) queryNodeForKeys(nodeAddr, pattern string) []string {
	fd, err := o.connectToNode(nodeAddr)
	if err != nil {
		log.Printf("[ORGID-AUTH] Failed to connect to node %s: %v", nodeAddr, err)
		return nil
	}
	defer syscall.Close(fd)

	return o.redisKeysSingleNode(fd, pattern)
}

// Redis HGET command with cluster support
func (o *OrgIDAuth) redisHGet(fd int, key, field string) string {
	if !o.clusterMode {
		return o.redisHGetSingleNode(fd, key, field)
	}
	return o.redisHGetCluster(fd, key, field)
}

// Redis HGET for cluster mode - handles MOVED redirects
func (o *OrgIDAuth) redisHGetCluster(fd int, key, field string) string {
	// Try the connected node first
	cmd := fmt.Sprintf("*3\r\n$4\r\nHGET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(key), key, len(field), field)
	_, err := syscall.Write(fd, []byte(cmd))
	if err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		return ""
	}

	response := string(buf[:n])

	// Check for MOVED redirect
	if strings.HasPrefix(response, "-MOVED") {
		// Parse MOVED response: -MOVED <slot> <ip:port>
		parts := strings.Fields(response)
		if len(parts) >= 3 {
			targetNode := parts[2]
			targetNode = strings.TrimSuffix(targetNode, "\r\n")

			// Query the correct node
			return o.queryNodeForHGet(targetNode, key, field)
		}
		return ""
	}

	// Parse normal response
	return o.parseHGetResponse(response)
}

// Query a specific node for HGET
func (o *OrgIDAuth) queryNodeForHGet(nodeAddr, key, field string) string {
	fd, err := o.connectToNode(nodeAddr)
	if err != nil {
		log.Printf("[ORGID-AUTH] Failed to connect to node %s: %v", nodeAddr, err)
		return ""
	}
	defer syscall.Close(fd)

	return o.redisHGetSingleNode(fd, key, field)
}

// Redis HGET for single node
func (o *OrgIDAuth) redisHGetSingleNode(fd int, key, field string) string {
	cmd := fmt.Sprintf("*3\r\n$4\r\nHGET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(key), key, len(field), field)
	_, err := syscall.Write(fd, []byte(cmd))
	if err != nil {
		return ""
	}

	// Read response into buffer
	buf := make([]byte, 4096)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		return ""
	}

	return o.parseHGetResponse(string(buf[:n]))
}

// Parse HGET response (bulk string format)
func (o *OrgIDAuth) parseHGetResponse(response string) string {
	reader := bufio.NewReader(bytes.NewReader([]byte(response)))
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	// Parse bulk string response
	firstLine = strings.TrimSpace(firstLine)
	if strings.HasPrefix(firstLine, "$-1") {
		return "" // nil response
	}
	if !strings.HasPrefix(firstLine, "$") {
		return ""
	}

	// Parse length
	lengthStr := firstLine[1:]
	length, err := strconv.Atoi(lengthStr)
	if err != nil || length < 0 {
		return ""
	}

	// Read exact number of bytes + \r\n
	valueBytes := make([]byte, length+2)
	_, err = reader.Read(valueBytes)
	if err != nil {
		return ""
	}

	// Extract value (without \r\n)
	value := string(valueBytes[:length])
	return value
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
					log.Printf("[ORGID-AUTH] Removing stale connection fd=%d (idle for %v)", conn.fd, time.Since(conn.lastUsed))
					syscall.Close(conn.fd)
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

	// Close the socket
	if conn.fd > 0 {
		syscall.Close(conn.fd)
		log.Printf("[ORGID-AUTH] Closed failed connection fd=%d", conn.fd)
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
		if conn.fd > 0 {
			syscall.Close(conn.fd)
			log.Printf("[ORGID-AUTH] Closed connection fd=%d during shutdown", conn.fd)
		}
	}
	p.connections = nil
}

// createConnection creates a new Redis connection
func (p *ConnectionPool) createConnection() (*Connection, error) {
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
		authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(p.redisPassword), p.redisPassword)
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
	}, nil
}