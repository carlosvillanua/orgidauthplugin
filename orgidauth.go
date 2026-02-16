package orgidauthplugin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	smallBufPool = sync.Pool{
		New: func() interface{} { return make([]byte, smallBufferSize) },
	}
	mediumBufPool = sync.Pool{
		New: func() interface{} { return make([]byte, mediumBufferSize) },
	}
	largeBufPool = sync.Pool{
		New: func() interface{} { return make([]byte, largeBufferSize) },
	}
)

func getSmallBuf() []byte {
	if v := smallBufPool.Get(); v != nil {
		if b, ok := v.([]byte); ok {
			return b
		}
	}
	return make([]byte, smallBufferSize)
}

func putSmallBuf(b []byte) {
	if b != nil && len(b) == smallBufferSize {
		smallBufPool.Put(b)
	}
}

func getMediumBuf() []byte {
	if v := mediumBufPool.Get(); v != nil {
		if b, ok := v.([]byte); ok {
			return b
		}
	}
	return make([]byte, mediumBufferSize)
}

func putMediumBuf(b []byte) {
	if b != nil && len(b) == mediumBufferSize {
		mediumBufPool.Put(b)
	}
}

func getLargeBuf() []byte {
	if v := largeBufPool.Get(); v != nil {
		if b, ok := v.([]byte); ok {
			return b
		}
	}
	return make([]byte, largeBufferSize)
}

func putLargeBuf(b []byte) {
	if b != nil && len(b) == largeBufferSize {
		largeBufPool.Put(b)
	}
}

func logJSON(level, msg string, fields map[string]interface{}) {
	entry := map[string]interface{}{
		"time":   time.Now().UTC().Format(time.RFC3339),
		"level":  level,
		"msg":    msg,
		"logger": "orgidauthplugin",
	}
	for k, v := range fields {
		entry[k] = v
	}
	if data, err := json.Marshal(entry); err == nil {
		os.Stdout.WriteString(string(data) + "\n")
	}
}

type Config struct {
	RedisAddr       string `json:"redisAddr,omitempty"`
	RedisUsername   string `json:"redisUsername,omitempty"`
	RedisPassword   string `json:"redisPassword,omitempty"`
	OrgHeader       string `json:"orgHeader,omitempty"`
	PoolSize        int    `json:"poolSize,omitempty"`
	MaxConnIdleTime string `json:"maxConnIdleTime,omitempty"`
	PoolWaitTimeout string `json:"poolWaitTimeout,omitempty"`
	CacheTTL        string `json:"cacheTTL,omitempty"`
	CacheMaxSize    int    `json:"cacheMaxSize,omitempty"`
	ClusterMode     bool   `json:"clusterMode,omitempty"`
	TLSMode         string `json:"tlsMode,omitempty"`
	KeyPrefix       string `json:"keyPrefix,omitempty"`
	FailOpen        bool   `json:"failOpen,omitempty"`
	RequestTimeout  string `json:"requestTimeout,omitempty"`
	Global          bool   `json:"global,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		RedisAddr:       "valkey-redis-master.traefik.svc.cluster.local:6379",
		RedisUsername:   "",
		RedisPassword:   "traefik",
		OrgHeader:       "X-Org",
		PoolSize:        500,
		MaxConnIdleTime: "5m",
		PoolWaitTimeout: "500ms",
		CacheTTL:        "10m",
		CacheMaxSize:    100000,
		ClusterMode:     true,
		TLSMode:         "secure",
		KeyPrefix:       "uuid",
		FailOpen:        true,
		RequestTimeout:  "5s",
	}
}

func (c *Config) Validate() error {
	if c.PoolSize <= 0 {
		return fmt.Errorf("poolSize must be positive, got %d", c.PoolSize)
	}
	if c.CacheMaxSize <= 0 {
		return fmt.Errorf("cacheMaxSize must be positive, got %d", c.CacheMaxSize)
	}
	if c.OrgHeader == "" {
		return fmt.Errorf("orgHeader cannot be empty")
	}
	if _, err := time.ParseDuration(c.MaxConnIdleTime); err != nil {
		return fmt.Errorf("invalid maxConnIdleTime '%s': %w", c.MaxConnIdleTime, err)
	}
	if _, err := time.ParseDuration(c.PoolWaitTimeout); err != nil {
		return fmt.Errorf("invalid poolWaitTimeout '%s': %w", c.PoolWaitTimeout, err)
	}
	if _, err := time.ParseDuration(c.CacheTTL); err != nil {
		return fmt.Errorf("invalid cacheTTL '%s': %w", c.CacheTTL, err)
	}
	if _, err := time.ParseDuration(c.RequestTimeout); err != nil {
		return fmt.Errorf("invalid requestTimeout '%s': %w", c.RequestTimeout, err)
	}
	if c.TLSMode == "" {
		c.TLSMode = "secure"
	}
	if c.TLSMode != "disabled" && c.TLSMode != "secure" && c.TLSMode != "insecure" {
		return fmt.Errorf("tlsMode must be 'disabled', 'secure', or 'insecure', got '%s'", c.TLSMode)
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "uuid"
	}
	return nil
}

type Connection struct {
	conn     net.Conn
	lastUsed time.Time
	inUse    bool
}

type ConnectionPool struct {
	connections     []*Connection
	pendingCount    int
	mutex           sync.Mutex
	available       chan struct{}
	redisAddr       string
	redisUsername   string
	redisPassword   string
	poolSize        int
	maxConnIdleTime time.Duration
	poolWaitTimeout time.Duration
	tlsMode         string
	closing         bool
}

type CacheEntry struct {
	allowed   bool
	expiresAt time.Time
	lastUsed  time.Time
}

type IPCache struct {
	entries  map[string]*CacheEntry
	mutex    sync.RWMutex
	maxSize  int
	cacheTTL time.Duration
}

type OrgAllowlistEntry struct {
	exactIPs    map[string]struct{}
	parsedCIDRs []*net.IPNet
	expiresAt   time.Time
	lastUsed    time.Time
}

type OrgAllowlistCache struct {
	entries  map[string]*OrgAllowlistEntry
	mutex    sync.RWMutex
	maxSize  int
	cacheTTL time.Duration
}

type OrgIDAuth struct {
	next              http.Handler
	orgHeader         string
	name              string
	pool              *ConnectionPool
	cache             *IPCache
	orgAllowlistCache *OrgAllowlistCache
	clusterMode       bool
	tlsMode           string
	keyPrefix         string
	failOpen          bool
	requestTimeout    time.Duration
	global            bool
}

const (
	redisReadTimeout    = 1 * time.Second
	redisWriteTimeout   = 1 * time.Second
	redisConnectTimeout = 2 * time.Second
	tcpKeepAlivePeriod  = 30 * time.Second
	poolRetryInterval   = 10 * time.Millisecond
)

const (
	smallBufferSize  = 1024
	mediumBufferSize = 65536
	largeBufferSize  = 131072
)

const (
	orgAllowlistCacheMaxSize = 100
	cacheEvictionPercent     = 10
	minEvictionCount         = 1
)

func writeWithTimeout(conn net.Conn, data []byte) (int, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(redisWriteTimeout)); err != nil {
		return 0, fmt.Errorf("set write deadline: %w", err)
	}
	n, err := conn.Write(data)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return n, fmt.Errorf("write: %w", err)
	}
	return n, nil
}

func readWithTimeout(conn net.Conn, buf []byte) (int, error) {
	if err := conn.SetReadDeadline(time.Now().Add(redisReadTimeout)); err != nil {
		return 0, fmt.Errorf("set read deadline: %w", err)
	}
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return n, fmt.Errorf("read: %w", err)
	}
	return n, nil
}

func setTCPKeepAlive(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			return
		}
		if err := tcpConn.SetKeepAlivePeriod(tcpKeepAlivePeriod); err != nil {
		}
		return
	}

}

func (o *OrgIDAuth) handleMovedRedirectBool(response string, retryFn func(net.Conn) bool) (bool, bool) {
	if !strings.HasPrefix(response, "-MOVED") {
		return false, false
	}

	parts := strings.Fields(response)
	if len(parts) < 3 {
		return false, false
	}

	nodeAddr := parts[2]
	nodeConn, err := o.connectToNode(nodeAddr)
	if err != nil {
		return false, false
	}
	defer nodeConn.Close()

	result := retryFn(nodeConn)
	return result, true
}

func (o *OrgIDAuth) handleMovedRedirectStringSlice(response string, retryFn func(net.Conn) ([]string, error)) ([]string, error, bool) {
	if !strings.HasPrefix(response, "-MOVED") {
		return nil, nil, false
	}

	parts := strings.Fields(response)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed MOVED response: %s", response), true
	}

	nodeAddr := parts[2]
	nodeConn, err := o.connectToNode(nodeAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to node after MOVED redirect: %w", err), true
	}
	defer nodeConn.Close()

	result, err := retryFn(nodeConn)
	return result, err, true
}

func (o *OrgIDAuth) handleMovedRedirectInt(response string, retryFn func(net.Conn) int) (int, bool) {
	if !strings.HasPrefix(response, "-MOVED") {
		return 0, false
	}

	parts := strings.Fields(response)
	if len(parts) < 3 {
		return -1, false
	}

	nodeAddr := parts[2]
	nodeConn, err := o.connectToNode(nodeAddr)
	if err != nil {
		return -1, false
	}
	defer nodeConn.Close()

	result := retryFn(nodeConn)
	return result, true
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

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

	requestTimeout, err := time.ParseDuration(config.RequestTimeout)
	if err != nil {
		requestTimeout = 5 * time.Second
	}

	pool := &ConnectionPool{
		connections:     make([]*Connection, 0, config.PoolSize),
		pendingCount:    0,
		available:       make(chan struct{}, 1),
		redisAddr:       config.RedisAddr,
		redisUsername:   config.RedisUsername,
		redisPassword:   config.RedisPassword,
		poolSize:        config.PoolSize,
		maxConnIdleTime: maxConnIdleTime,
		poolWaitTimeout: poolWaitTimeout,
		tlsMode:         config.TLSMode,
		closing:         false,
	}

	cache := &IPCache{
		entries:  make(map[string]*CacheEntry),
		maxSize:  config.CacheMaxSize,
		cacheTTL: cacheTTL,
	}

	orgAllowlistCache := &OrgAllowlistCache{
		entries:  make(map[string]*OrgAllowlistEntry),
		maxSize:  orgAllowlistCacheMaxSize,
		cacheTTL: cacheTTL,
	}

	return &OrgIDAuth{
		next:              next,
		orgHeader:         config.OrgHeader,
		name:              name,
		pool:              pool,
		cache:             cache,
		orgAllowlistCache: orgAllowlistCache,
		clusterMode:       config.ClusterMode,
		tlsMode:           config.TLSMode,
		keyPrefix:         config.KeyPrefix,
		failOpen:          config.FailOpen,
		requestTimeout:    requestTimeout,
		global:            config.Global,
	}, nil
}

func (o *OrgIDAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodOptions {
		o.next.ServeHTTP(rw, req)
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), o.requestTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		http.Error(rw, "Request cancelled", http.StatusRequestTimeout)
		return
	default:
	}

	clientIP := o.getClientIP(req)

	orgHeaders := req.Header.Values(o.orgHeader)
	var orgIDs []string

	for _, orgHeader := range orgHeaders {
		if orgHeader != "" {
			if strings.Contains(orgHeader, ",") {
				for _, orgID := range strings.Split(orgHeader, ",") {
					trimmed := strings.TrimSpace(orgID)
					if trimmed != "" {
						orgIDs = append(orgIDs, trimmed)
					}
				}
			} else {
				trimmed := strings.TrimSpace(orgHeader)
				if trimmed != "" {
					orgIDs = append(orgIDs, trimmed)
				}
			}
		}
	}

	if len(orgIDs) == 0 {
		o.next.ServeHTTP(rw, req)
		return
	}

	for _, orgID := range orgIDs {

		select {
		case <-ctx.Done():
			http.Error(rw, "Request timeout", http.StatusRequestTimeout)
			return
		default:
		}

		cacheKey := orgID + ":" + clientIP
		if cached, ok := o.cache.get(cacheKey); ok {
			if cached {
				o.next.ServeHTTP(rw, req)
				return
			}
			continue
		}

		allowed, shouldCache := o.isIPAllowedForOrg(ctx, orgID, clientIP)

		if shouldCache {
			o.cache.set(cacheKey, allowed, time.Now().Add(o.cache.cacheTTL))
		}

		if allowed {
			o.next.ServeHTTP(rw, req)
			return
		}

	}

	http.Error(rw, "IP not allowed for any organization", http.StatusForbidden)
}

func (o *OrgIDAuth) isIPAllowedForOrg(ctx context.Context, orgID, clientIP string) (bool, bool) {
	var exactIPs map[string]struct{}
	var parsedCIDRs []*net.IPNet

	if cachedIPs, cachedCIDRs, ok := o.orgAllowlistCache.get(orgID); ok {
		exactIPs = cachedIPs
		parsedCIDRs = cachedCIDRs
	} else {

		select {
		case <-ctx.Done():
			return o.failOpen, false
		default:
		}

		conn, err := o.pool.getConnectionWithContext(ctx)
		if err != nil {
			return o.failOpen, false
		}

		connFailed := false
		defer func() {
			if connFailed {
				o.pool.removeConnection(conn)
			} else {
				o.pool.returnConnection(conn)
			}
		}()

		key := fmt.Sprintf("%s:{%s}:allowed", o.keyPrefix, orgID)

		members, err := o.redisSMembers(conn.conn, key)
		if err != nil {
			connFailed = true
			return o.failOpen, false
		}

		if len(members) == 0 {
			o.orgAllowlistCache.set(orgID, members, time.Now().Add(o.orgAllowlistCache.cacheTTL))
			return true, true
		}

		o.orgAllowlistCache.set(orgID, members, time.Now().Add(o.orgAllowlistCache.cacheTTL))
		exactIPs, parsedCIDRs, _ = o.orgAllowlistCache.get(orgID)
	}

	if len(exactIPs) == 0 && len(parsedCIDRs) == 0 {
		return true, true
	}

	if _, found := exactIPs[clientIP]; found {
		return true, true
	}

	if len(parsedCIDRs) > 0 {
		clientIPParsed := net.ParseIP(clientIP)
		if clientIPParsed == nil {
			return false, true
		}

		for _, ipnet := range parsedCIDRs {
			if ipnet.Contains(clientIPParsed) {
				return true, true
			}
		}
	}

	return false, true
}

func (o *OrgIDAuth) redisSMembers(conn net.Conn, key string) ([]string, error) {
	members, response, err := o.redisSMembersInternal(conn, key)
	if err != nil {
		return nil, err
	}

	if o.clusterMode {
		if result, err, wasRedirected := o.handleMovedRedirectStringSlice(response, func(nodeConn net.Conn) ([]string, error) {
			m, _, e := o.redisSMembersInternal(nodeConn, key)
			return m, e
		}); wasRedirected {
			return result, err
		}
	}

	return members, nil
}

func (o *OrgIDAuth) redisSMembersInternal(conn net.Conn, key string) ([]string, string, error) {
	cmd := fmt.Sprintf("*2\r\n$8\r\nSMEMBERS\r\n$%d\r\n%s\r\n", len(key), key)
	_, err := writeWithTimeout(conn, []byte(cmd))
	if err != nil {
		return nil, "", fmt.Errorf("write SMEMBERS command for key %s: %w", key, err)
	}

	buf := getMediumBuf()
	defer putMediumBuf(buf)
	n, err := readWithTimeout(conn, buf)
	if err != nil {
		return nil, "", fmt.Errorf("read SMEMBERS response for key %s: %w", key, err)
	}

	dataCopy := make([]byte, n)
	copy(dataCopy, buf[:n])

	reader := bufio.NewReader(bytes.NewReader(dataCopy))
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", fmt.Errorf("parse SMEMBERS response: %w", err)
	}

	response = strings.TrimSpace(response)

	if strings.HasPrefix(response, "-MOVED") {
		return nil, response, nil
	}

	if !strings.HasPrefix(response, "*") {
		return nil, response, fmt.Errorf("invalid SMEMBERS response format: %s", response)
	}

	countStr := response[1:]
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return nil, response, fmt.Errorf("parse SMEMBERS count: %w", err)
	}
	if count == 0 {
		return []string{}, response, nil
	}

	members := make([]string, 0, count)
	for i := 0; i < count; i++ {
		lenLine, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		lenLine = strings.TrimSpace(lenLine)
		if !strings.HasPrefix(lenLine, "$") {
			continue
		}

		lengthStr := lenLine[1:]
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length < 0 {
			continue
		}

		memberBytes := make([]byte, length+2)
		_, err = reader.Read(memberBytes)
		if err != nil {
			break
		}

		member := string(memberBytes[:length])
		members = append(members, member)
	}

	return members, response, nil
}

func (o *OrgIDAuth) redisKeys(conn net.Conn, pattern string) []string {
	if !o.clusterMode {
		return o.redisKeysSingleNode(conn, pattern)
	}

	return o.redisKeysCluster(conn, pattern)
}

func (o *OrgIDAuth) redisKeysSingleNode(conn net.Conn, pattern string) []string {
	cmd := fmt.Sprintf("*2\r\n$4\r\nKEYS\r\n$%d\r\n%s\r\n", len(pattern), pattern)
	_, err := writeWithTimeout(conn, []byte(cmd))
	if err != nil {
		return nil
	}

	buf := getMediumBuf()
	defer putMediumBuf(buf)
	n, err := readWithTimeout(conn, buf)
	if err != nil {
		return nil
	}

	dataCopy := make([]byte, n)
	copy(dataCopy, buf[:n])

	reader := bufio.NewReader(bytes.NewReader(dataCopy))
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

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

	keys := make([]string, 0, count)
	for i := 0; i < count; i++ {
		lenLine, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		lenLine = strings.TrimSpace(lenLine)
		if !strings.HasPrefix(lenLine, "$") {
			continue
		}

		lengthStr := lenLine[1:]
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length < 0 {
			continue
		}

		keyBytes := make([]byte, length+2)
		_, err = reader.Read(keyBytes)
		if err != nil {
			break
		}

		key := string(keyBytes[:length])
		keys = append(keys, key)
	}

	return keys
}

func (o *OrgIDAuth) redisKeysCluster(conn net.Conn, pattern string) []string {
	nodes := o.getClusterNodes(conn)
	if len(nodes) == 0 {
		return o.redisKeysSingleNode(conn, pattern)
	}

	allKeys := make(map[string]bool)
	for _, nodeAddr := range nodes {
		nodeKeys := o.queryNodeForKeys(nodeAddr, pattern)
		for _, key := range nodeKeys {
			allKeys[key] = true
		}
	}

	keys := make([]string, 0, len(allKeys))
	for key := range allKeys {
		keys = append(keys, key)
	}

	return keys
}

func (o *OrgIDAuth) getClusterNodes(conn net.Conn) []string {
	cmd := "*2\r\n$7\r\nCLUSTER\r\n$5\r\nNODES\r\n"
	_, err := writeWithTimeout(conn, []byte(cmd))
	if err != nil {
		return nil
	}

	buf := getLargeBuf()
	defer putLargeBuf(buf)
	n, err := readWithTimeout(conn, buf)
	if err != nil {
		return nil
	}

	response := string(buf[:n])

	if !strings.HasPrefix(response, "$") {
		return nil
	}

	lines := strings.Split(response, "\r\n")
	if len(lines) < 2 {
		return nil
	}

	nodesData := lines[1]

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

		addrParts := strings.Split(fields[1], "@")
		if len(addrParts) > 0 {
			addr := addrParts[0]

			if !strings.Contains(fields[2], "slave") && !strings.Contains(fields[2], "replica") {
				nodes = append(nodes, addr)
			}
		}
	}

	return nodes
}

func (o *OrgIDAuth) connectToNode(nodeAddr string) (net.Conn, error) {
	var conn net.Conn
	var err error

	if o.tlsMode == "disabled" {
		conn, err = net.DialTimeout("tcp", nodeAddr, redisConnectTimeout)
		if err != nil {
			return nil, fmt.Errorf("connect to %s: %w", nodeAddr, err)
		}
	} else {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: o.tlsMode == "insecure",
		}
		dialer := &net.Dialer{Timeout: redisConnectTimeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", nodeAddr, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("connect with TLS to %s: %w", nodeAddr, err)
		}
	}

	setTCPKeepAlive(conn)

	if o.pool.redisPassword != "" {
		if err := o.authenticateConnection(conn); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func (o *OrgIDAuth) authenticateConnection(conn net.Conn) error {
	var authCmd string
	if o.pool.redisUsername != "" {
		authCmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			len(o.pool.redisUsername), o.pool.redisUsername,
			len(o.pool.redisPassword), o.pool.redisPassword)
	} else {
		authCmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(o.pool.redisPassword), o.pool.redisPassword)
	}

	if _, err := writeWithTimeout(conn, []byte(authCmd)); err != nil {
		return fmt.Errorf("write AUTH command: %w", err)
	}

	buf := getSmallBuf()
	defer putSmallBuf(buf)
	n, err := readWithTimeout(conn, buf)
	if err != nil {
		return fmt.Errorf("read AUTH response: %w", err)
	}

	if !strings.Contains(string(buf[:n]), "+OK") {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func (o *OrgIDAuth) queryNodeForKeys(nodeAddr, pattern string) []string {
	conn, err := o.connectToNode(nodeAddr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	return o.redisKeysSingleNode(conn, pattern)
}

func (o *OrgIDAuth) redisSIsMember(conn net.Conn, key, member string) bool {
	cmd := fmt.Sprintf("*3\r\n$9\r\nSISMEMBER\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
		len(key), key, len(member), member)
	_, err := writeWithTimeout(conn, []byte(cmd))
	if err != nil {
		return false
	}

	buf := getSmallBuf()
	defer putSmallBuf(buf)
	n, err := readWithTimeout(conn, buf)
	if err != nil {
		return false
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	if o.clusterMode {
		if result, wasRedirected := o.handleMovedRedirectBool(response, func(nodeConn net.Conn) bool {
			return o.redisSIsMember(nodeConn, key, member)
		}); wasRedirected {
			return result
		}
	}

	response = strings.TrimSpace(response)
	return response == ":1"
}

func (o *OrgIDAuth) redisExists(conn net.Conn, key string) int {
	cmd := fmt.Sprintf("*2\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n", len(key), key)
	_, err := writeWithTimeout(conn, []byte(cmd))
	if err != nil {
		return -1
	}

	buf := getSmallBuf()
	defer putSmallBuf(buf)
	n, err := readWithTimeout(conn, buf)
	if err != nil {
		return -1
	}

	reader := bufio.NewReader(bytes.NewReader(buf[:n]))
	response, err := reader.ReadString('\n')
	if err != nil {
		return -1
	}

	if o.clusterMode {
		if result, wasRedirected := o.handleMovedRedirectInt(response, func(nodeConn net.Conn) int {
			return o.redisExists(nodeConn, key)
		}); wasRedirected {
			return result
		}
	}

	response = strings.TrimSpace(response)
	if response == ":1" {
		return 1
	} else if response == ":0" {
		return 0
	}

	return -1
}

func getHeaderCaseInsensitive(headers http.Header, name string) string {
	lower := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == lower && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func (o *OrgIDAuth) getClientIP(req *http.Request) string {
	if o.global {
		if fwd := getHeaderCaseInsensitive(req.Header, "forwarded"); fwd != "" {
			for _, part := range strings.Split(fwd, ";") {
				part = strings.TrimSpace(part)
				lower := strings.ToLower(part)
				if strings.HasPrefix(lower, "for=") {
					ip := part[4:]
					ip = strings.Trim(ip, `"`)
					if bracketIdx := strings.Index(ip, "["); bracketIdx >= 0 {
						if endBracket := strings.Index(ip, "]"); endBracket > bracketIdx {
							ip = ip[bracketIdx+1 : endBracket]
						}
					}
					if host, _, err := net.SplitHostPort(ip); err == nil {
						ip = host
					}
					if isValidIP(ip) {
						return ip
					}
				}
			}
		}
	}

	if xri := getHeaderCaseInsensitive(req.Header, "x-real-ip"); xri != "" && isValidIP(xri) {
		return xri
	}

	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (c *IPCache) get(key string) (bool, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		return false, false
	}

	if time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return false, false
	}

	entry.lastUsed = time.Now()

	return entry.allowed, true
}

func (c *IPCache) set(key string, allowed bool, expiresAt time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	c.entries[key] = &CacheEntry{
		allowed:   allowed,
		expiresAt: expiresAt,
		lastUsed:  time.Now(),
	}
}

func (c *IPCache) evictLRU() {
	now := time.Now()

	toDelete := make([]string, 0)
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		delete(c.entries, key)
	}

	if len(c.entries) >= c.maxSize {
		count := len(c.entries) / cacheEvictionPercent
		if count < minEvictionCount {
			count = minEvictionCount
		}

		type lruEntry struct {
			key      string
			lastUsed time.Time
		}

		entries := make([]lruEntry, 0, len(c.entries))
		for key, entry := range c.entries {
			entries = append(entries, lruEntry{key: key, lastUsed: entry.lastUsed})
		}

		for i := 0; i < count && i < len(entries); i++ {
			oldestIdx := i
			for j := i + 1; j < len(entries); j++ {
				if entries[j].lastUsed.Before(entries[oldestIdx].lastUsed) {
					oldestIdx = j
				}
			}
			if oldestIdx != i {
				entries[i], entries[oldestIdx] = entries[oldestIdx], entries[i]
			}
			delete(c.entries, entries[i].key)
		}
	}
}

func (c *OrgAllowlistCache) get(orgID string) (map[string]struct{}, []*net.IPNet, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, exists := c.entries[orgID]
	if !exists {
		return nil, nil, false
	}

	if time.Now().After(entry.expiresAt) {
		delete(c.entries, orgID)
		return nil, nil, false
	}

	entry.lastUsed = time.Now()

	return entry.exactIPs, entry.parsedCIDRs, true
}

func (c *OrgAllowlistCache) set(orgID string, members []string, expiresAt time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	exactIPs := make(map[string]struct{}, len(members))
	parsedCIDRs := make([]*net.IPNet, 0)

	for _, member := range members {
		member = strings.TrimSpace(member)
		if member == "" {
			continue
		}
		if strings.Contains(member, "/") {
			_, ipnet, err := net.ParseCIDR(member)
			if err != nil {
				continue
			}
			parsedCIDRs = append(parsedCIDRs, ipnet)
		} else {
			exactIPs[member] = struct{}{}
		}
	}

	c.entries[orgID] = &OrgAllowlistEntry{
		exactIPs:    exactIPs,
		parsedCIDRs: parsedCIDRs,
		expiresAt:   expiresAt,
		lastUsed:    time.Now(),
	}
}

func (c *OrgAllowlistCache) evictLRU() {
	now := time.Now()

	toDelete := make([]string, 0)
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		delete(c.entries, key)
	}

	if len(c.entries) >= c.maxSize {
		count := len(c.entries) / cacheEvictionPercent
		if count < minEvictionCount {
			count = minEvictionCount
		}

		type lruEntry struct {
			key      string
			lastUsed time.Time
		}

		entries := make([]lruEntry, 0, len(c.entries))
		for key, entry := range c.entries {
			entries = append(entries, lruEntry{key: key, lastUsed: entry.lastUsed})
		}

		for i := 0; i < count && i < len(entries); i++ {
			oldestIdx := i
			for j := i + 1; j < len(entries); j++ {
				if entries[j].lastUsed.Before(entries[oldestIdx].lastUsed) {
					oldestIdx = j
				}
			}
			if oldestIdx != i {
				entries[i], entries[oldestIdx] = entries[oldestIdx], entries[i]
			}
			delete(c.entries, entries[i].key)
		}
	}
}

func (p *ConnectionPool) getConnectionWithContext(ctx context.Context) (*Connection, error) {
	startTime := time.Now()

	for {

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		p.mutex.Lock()

		if p.closing {
			p.mutex.Unlock()
			return nil, fmt.Errorf("connection pool is closing")
		}

		for i := len(p.connections) - 1; i >= 0; i-- {
			conn := p.connections[i]
			if !conn.inUse {
				if time.Since(conn.lastUsed) > p.maxConnIdleTime {
					conn.conn.Close()
					p.connections = append(p.connections[:i], p.connections[i+1:]...)
					continue
				}

				conn.inUse = true
				conn.lastUsed = time.Now()
				p.mutex.Unlock()
				return conn, nil
			}
		}

		if len(p.connections)+p.pendingCount < p.poolSize {
			p.pendingCount++
			p.mutex.Unlock()

			conn, err := p.createConnection()

			p.mutex.Lock()
			p.pendingCount--
			if err != nil {
				p.mutex.Unlock()
				return nil, fmt.Errorf("create connection: %w", err)
			}
			conn.inUse = true
			p.connections = append(p.connections, conn)
			p.mutex.Unlock()

			select {
			case p.available <- struct{}{}:
			default:
			}

			return conn, nil
		}

		p.mutex.Unlock()

		remaining := p.poolWaitTimeout - time.Since(startTime)
		if remaining <= 0 {
			return nil, fmt.Errorf("connection pool exhausted after %v wait", p.poolWaitTimeout)
		}

		select {
		case <-p.available:

			continue
		case <-time.After(poolRetryInterval):

			continue
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled while waiting for connection: %w", ctx.Err())
		}
	}
}

func (p *ConnectionPool) getConnection() (*Connection, error) {
	return p.getConnectionWithContext(context.Background())
}

func (p *ConnectionPool) returnConnection(conn *Connection) {
	p.mutex.Lock()
	conn.inUse = false
	conn.lastUsed = time.Now()
	p.mutex.Unlock()

	select {
	case p.available <- struct{}{}:
	default:
	}
}

func (p *ConnectionPool) removeConnection(conn *Connection) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if conn.conn != nil {
		conn.conn.Close()
	}

	for i, c := range p.connections {
		if c == conn {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			break
		}
	}
}

func (p *ConnectionPool) Close() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.closing = true

	for _, conn := range p.connections {
		if conn != nil && conn.conn != nil {
			conn.conn.Close()
		}
	}
	p.connections = nil

	close(p.available)
}

func (p *ConnectionPool) Stats() map[string]interface{} {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	total := len(p.connections)
	inUse := 0
	idle := 0

	for _, conn := range p.connections {
		if conn == nil {
			continue
		}
		if conn.inUse {
			inUse++
		} else {
			idle++
		}
	}

	utilizationPct := float64(0)
	if p.poolSize > 0 {
		utilizationPct = float64(inUse) / float64(p.poolSize) * 100
	}

	return map[string]interface{}{
		"total":       total,
		"in_use":      inUse,
		"idle":        idle,
		"pending":     p.pendingCount,
		"max_size":    p.poolSize,
		"utilization": utilizationPct,
	}
}

func (p *ConnectionPool) createConnection() (*Connection, error) {
	var conn net.Conn
	var err error

	if p.tlsMode == "disabled" {
		conn, err = net.DialTimeout("tcp", p.redisAddr, redisConnectTimeout)
		if err != nil {
			return nil, fmt.Errorf("connect to %s: %w", p.redisAddr, err)
		}
	} else {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: p.tlsMode == "insecure",
		}
		dialer := &net.Dialer{Timeout: redisConnectTimeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", p.redisAddr, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("connect with TLS to %s: %w", p.redisAddr, err)
		}
	}

	setTCPKeepAlive(conn)

	if p.redisPassword != "" {
		var authCmd string
		if p.redisUsername != "" {
			authCmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
				len(p.redisUsername), p.redisUsername,
				len(p.redisPassword), p.redisPassword)
		} else {
			authCmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(p.redisPassword), p.redisPassword)
		}

		_, err = writeWithTimeout(conn, []byte(authCmd))
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("send auth command: %w", err)
		}

		buf := getSmallBuf()
		defer putSmallBuf(buf)
		n, err := readWithTimeout(conn, buf)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read auth response: %w", err)
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
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
