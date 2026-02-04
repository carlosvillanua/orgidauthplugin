# OrgID Auth Plugin

A Traefik middleware plugin for organization-based IP authentication using Redis/Valkey.

## ⚠️ Disclaimer

This plugin is provided **AS IS** as a reference implementation. You must adapt and validate it for your environment.

**Your Responsibilities:**
- Security audits and testing
- Production readiness assessment
- Fail-open policy review
- Infrastructure-specific configuration

Use at your own risk. No warranties or support commitments.

## Features

- **IP Allowlist Enforcement**: Validates client IPs against org-specific allowlists in Redis/Valkey
- **CIDR Block Support**: Supports both individual IPs and CIDR notation (e.g., `10.0.0.0/24`)
- **Multi-Organization Support**: Allows access if ANY organization permits the client IP
- **Redis Cluster Support**: Full cluster support with automatic node discovery and routing
- **Configurable Fail-Open Policy**: Allows requests when Redis is unavailable (configurable via `failOpen`)
- **Connection Pooling**: Efficient Redis connection management with context-aware timeouts
- **Multi-Level Caching**: IP decision cache + org allowlist cache with LRU eviction
- **TLS/SSL Support**: Configurable TLS modes (`secure`, `insecure`, `disabled`) for Redis connections
- **Buffer Pooling**: Reuses buffers to reduce memory allocations under load
- **Structured JSON Logging**: Only logs errors, not successful requests
- **Request Timeouts**: Configurable per-request timeout with context cancellation

## Quick Start

### 1. Install Plugin

**Helm:**
```bash
helm upgrade traefik traefik/traefik -n traefik --wait \
  --reuse-values \
  --set experimental.plugins.orgidauthplugin.moduleName=github.com/carlosvillanua/orgidauthplugin \
  --set experimental.plugins.orgidauthplugin.version=v0.1.12
```

**Static Config (`traefik.yml`):**
```yaml
experimental:
  plugins:
    orgidauthplugin:
      moduleName: github.com/carlosvillanua/orgidauthplugin
      version: v0.1.12
```

### 2. Create Middleware

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: orgid-auth
  namespace: apps
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "redis-master.default.svc.cluster.local:6379"
      redisUsername: "default"
      redisPassword: "your-password"
      orgHeader: "X-Org"
      poolSize: 500
      cacheTTL: "10m"
      clusterMode: true
      tlsMode: "secure"
      keyPrefix: "uuid"
      failOpen: true
      requestTimeout: "5s"
```

### 3. Apply to Route

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: protected-api
  namespace: apps
spec:
  entryPoints:
    - websecure
  routes:
    - kind: Rule
      match: Host(`api.example.com`)
      services:
        - name: api-service
          port: 8080
      middlewares:
        - name: jwt-authentication  # Must run first to set X-Org header
        - name: orgid-auth          # Then validates IP
```

## Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `redisAddr` | string | `valkey-redis-master.traefik.svc.cluster.local:6379` | Redis server address |
| `redisUsername` | string | `""` | Redis username (Redis 6+ ACL) |
| `redisPassword` | string | `traefik` | Redis password |
| `orgHeader` | string | `X-Org` | Header containing org IDs (set by JWT middleware) |
| `poolSize` | int | `500` | Max Redis connections |
| `maxConnIdleTime` | duration | `5m` | Max idle time before closing connection |
| `poolWaitTimeout` | duration | `500ms` | Max wait for available connection |
| `cacheTTL` | duration | `10m` | Cache entry TTL |
| `cacheMaxSize` | int | `100000` | Max cached IP entries |
| `clusterMode` | bool | `true` | Enable Redis Cluster support |
| `tlsMode` | string | `secure` | TLS mode: `disabled`, `secure`, or `insecure` |
| `keyPrefix` | string | `uuid` | Redis key prefix for allowlist keys |
| `failOpen` | bool | `true` | Allow traffic when Redis is unavailable |
| `requestTimeout` | duration | `5s` | Max time for request processing |

## Redis Cluster

For Redis Cluster deployments:

```yaml
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "redis-cluster.default.svc.cluster.local:6379"
      redisUsername: "default"
      redisPassword: "your-password"
      clusterMode: true
      poolSize: 500
      cacheTTL: "1s"     # Lower for faster updates
```

**How it works:**
- Handles `MOVED` redirects for `EXISTS`, `SISMEMBER`, and `SMEMBERS` commands
- Automatically routes requests to the correct cluster node
- Uses hash tags in keys (`{keyPrefix}:{orgID}:allowed`) for consistent cluster slot routing
- Discovers cluster nodes via `CLUSTER NODES` command

**⚠️ Important:** Without `clusterMode: true`, `MOVED` redirects are not handled, which may cause errors when keys are on different nodes.

## TLS/SSL Support

The plugin supports encrypted TLS connections to Redis/Valkey via the `tlsMode` parameter:

- `secure` (default) — TLS enabled with full certificate verification
- `insecure` — TLS enabled but certificate verification is skipped (for testing with self-signed certs)
- `disabled` — plain TCP connection, no TLS

```yaml
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "redis-cluster.traefik.svc.cluster.local:6380"
      redisUsername: "admin"
      redisPassword: "traefik"
      clusterMode: true
      tlsMode: "secure"
```

**Insecure mode (testing only):**
```yaml
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "redis-cluster.traefik.svc.cluster.local:6380"
      redisUsername: "admin"
      redisPassword: "traefik"
      clusterMode: true
      tlsMode: "insecure"  # Skips certificate verification
```

**How it works:**
- When `tlsMode` is `secure` or `insecure`, the plugin establishes TLS connections using Go's `crypto/tls` package
- `tlsMode: "insecure"` disables certificate verification (useful for testing with self-signed certs)
- `tlsMode: "disabled"` uses plain TCP connections (no encryption)
- Works with both single-node and cluster Redis deployments
- Standard TLS port for Redis is 6380 (plain text is 6379)

**⚠️ Security Notes:**
- Always use `tlsMode: "secure"` in production
- Only use `tlsMode: "insecure"` for testing environments
- Ensure Redis/Valkey is configured with valid TLS certificates
- Use proper certificate management (cert-manager, Vault, etc.)

## Redis Data Management

**Data Structure:**
```bash
# Pattern: {keyPrefix}:{orgID}:allowed (default keyPrefix is "uuid")
# Type: SET
# Members: Individual IPs or CIDR blocks
# Note: Hash tag braces {} around orgID ensure cluster slot consistency

# Individual IPs
SADD "uuid:{org-123}:allowed" "10.0.1.5"
SADD "uuid:{org-123}:allowed" "192.168.1.100"

# CIDR blocks
SADD "uuid:{org-123}:allowed" "10.42.0.0/16"
SADD "uuid:{org-123}:allowed" "192.168.0.0/24"

# Mixed (both IPs and CIDRs)
SADD "uuid:{org-456}:allowed" "172.16.50.100" "10.0.0.0/8" "192.168.1.0/24"
```

**Managing Allowlists:**
```bash
# Add individual IPs to allowlist
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SADD "uuid:{org-123}:allowed" "10.0.1.5" "192.168.1.100"

# Add CIDR blocks to allowlist
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SADD "uuid:{org-123}:allowed" "10.42.0.0/16" "192.168.0.0/24"

# Add mixed (IPs and CIDRs)
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SADD "uuid:{org-123}:allowed" "172.16.50.100" "10.0.0.0/8"

# View all allowed IPs/CIDRs
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SMEMBERS "uuid:{org-123}:allowed"

# Check if specific IP is allowed (exact match only)
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SISMEMBER "uuid:{org-123}:allowed" "10.0.1.5"

# Remove IP or CIDR from allowlist
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SREM "uuid:{org-123}:allowed" "10.0.1.5"

# Remove entire allowlist
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  DEL "uuid:{org-123}:allowed"
```

## How It Works

1. **JWT middleware** extracts org IDs from token and sets `X-Org` header
2. **Plugin extracts** client IP from `X-Forwarded-For`, `X-Real-IP`, or `RemoteAddr`
3. **No org header?** Request passes through (no authentication required)
4. **For each org ID**:
   - Check in-memory IP cache for `orgID:clientIP`
   - Check org allowlist cache for parsed IPs/CIDRs
   - On cache miss, fetch all members with `SMEMBERS` from Redis
   - Check exact IP match, then check CIDR ranges
5. **Decision**:
   - ✅ Allow if ANY org permits the IP (exact match or CIDR range)
   - ✅ Allow if org has no allowlist in Redis (empty set)
   - ✅ Allow if Redis unavailable (when `failOpen: true`)
   - ❌ Deny if org exists but IP not allowed

**Caching:**
- **IP Cache**: Caches allow/deny decisions per `orgID:clientIP` pair (configurable TTL and max size)
- **Org Allowlist Cache**: Caches parsed CIDR blocks and exact IPs per organization (up to 100 orgs)
- Both caches use LRU eviction when full

**Logging:**
- Structured JSON logging to stdout
- No logs for successful requests
- ERROR logs for Redis connection and command failures

## Version History

### v0.1.12 (2026-02-04)
- Major refactor: replaced raw syscall-based connections with `net.Conn` throughout
- Removed platform-specific files (`select_darwin.go`, `select_linux.go`)
- Replaced `tlsEnabled`/`tlsCABundle`/`tlsInsecureSkipVerify` with unified `tlsMode` (`disabled`/`secure`/`insecure`)
- Added configurable `keyPrefix`, `failOpen`, and `requestTimeout` parameters
- Added org allowlist cache with parsed CIDR blocks for faster lookups
- Added buffer pooling (`sync.Pool`) to reduce memory allocations
- Added context-aware request handling with configurable timeouts
- Changed key format to use hash tags (`{keyPrefix}:{orgID}:allowed`) for Redis Cluster slot consistency
- Missing org header now passes request through instead of returning 401
- Switched from `log.Printf` to structured JSON logging
- Improved connection pool with pending count tracking and channel-based signaling
- Updated defaults: `poolSize` 10→500, `cacheTTL` 30s→10m, `cacheMaxSize` 1000→100000, `clusterMode` default now `true`

### v0.1.11 (2026-01-28)
- Added TLS/SSL support for Redis/Valkey connections
- Supports both single-node and cluster TLS connections
- Configurable CA bundle for certificate verification
- Optional insecure skip verify for testing environments
- Backwards compatible with non-TLS deployments

### v0.1.10 (2026-01-27)
- Added Redis username (ACL) support for Redis 6+
- Updated AUTH command to support both username+password and password-only modes
- Backwards compatible with Redis versions < 6

### v0.1.9 (2026-01-26)
- Added CIDR block support for IP allowlists
- Implemented SMEMBERS command for single node and cluster mode
- Supports mixed allowlists with both individual IPs and CIDR ranges
- Fast path for exact IP matches, fallback to CIDR checking
- Feature parity with Traefik's built-in IPAllowList middleware

### v0.1.8 (2026-01-26)
- Fixed critical FD ownership bug causing Redis protocol leaks into HTTP responses
- Replaced os.NewFile() with direct syscall.Read() to prevent FD reuse issues
- Resolves "Unsolicited response received on idle HTTP channel" errors under load
- Stable performance at 300+ req/s with zero errors

### v0.1.7 (2026-01-26)
- Simplified key pattern to `uuid:{orgID}:allowed` for better performance
- Replaced KEYS pattern search with direct EXISTS + SISMEMBER lookups
- Added cluster support for EXISTS command with MOVED redirect handling
- Significantly improved Redis operation efficiency

### v0.1.5 (2026-01-25)
- Refactored cluster connection logic
- Reduced code duplication

### v0.1.4 (2026-01-25)
- Fixed cluster HGET for keys on different nodes
- Added MOVED redirect handling

### v0.1.3 (2026-01-25)
- Added Redis Cluster support
- Cluster-aware KEYS and node discovery
- New `clusterMode` config option

### v0.1.1 (2026-01-07)
- Fixed duration parsing from YAML

### v0.1.0 (2026-01-07)
- Initial release

## License

MIT
