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
- **Fail-Open Policy**: Allows requests when Redis is unavailable or org doesn't exist
- **Connection Pooling**: Efficient Redis connection management with stale connection cleanup
- **In-Memory Caching**: Configurable TTL-based caching reduces Redis load
- **Minimal Logging**: Only logs errors and warnings, not successful requests

## Quick Start

### 1. Install Plugin

**Helm:**
```bash
helm upgrade traefik traefik/traefik -n traefik --wait \
  --reuse-values \
  --set experimental.plugins.orgidauthplugin.moduleName=github.com/carlosvillanua/orgidauthplugin \
  --set experimental.plugins.orgidauthplugin.version=v0.1.9
```

**Static Config (`traefik.yml`):**
```yaml
experimental:
  plugins:
    orgidauthplugin:
      moduleName: github.com/carlosvillanua/orgidauthplugin
      version: v0.1.9
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
      poolSize: 10
      cacheTTL: "30s"
      clusterMode: false  # Set to true for Redis Cluster
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
| `poolSize` | int | `10` | Max Redis connections |
| `maxConnIdleTime` | duration | `5m` | Max idle time before closing connection |
| `poolWaitTimeout` | duration | `2s` | Max wait for available connection |
| `cacheTTL` | duration | `30s` | Cache entry TTL |
| `cacheMaxSize` | int | `1000` | Max cached entries |
| `clusterMode` | bool | `false` | Enable Redis Cluster support |
| `tlsEnabled` | bool | `false` | Enable TLS/SSL for Redis connections |
| `tlsCABundle` | string | `""` | PEM-encoded CA certificate bundle for TLS verification |
| `tlsInsecureSkipVerify` | bool | `false` | Skip TLS certificate verification (insecure, for testing only) |

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
      poolSize: 100      # Higher for cluster
      cacheTTL: "1s"     # Lower for faster updates
```

**How it works:**
- Handles `MOVED` redirects for `EXISTS` and `SISMEMBER` commands
- Automatically routes requests to the correct cluster node
- Ensures consistent key lookup across cluster shards

**⚠️ Important:** Without `clusterMode: true`, `MOVED` redirects are not handled, which may cause errors when keys are on different nodes.

## TLS/SSL Support

The plugin supports encrypted TLS connections to Redis/Valkey:

```yaml
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "redis-cluster.traefik.svc.cluster.local:6380"
      redisUsername: "admin"
      redisPassword: "traefik"
      clusterMode: true
      tlsEnabled: true
      tlsInsecureSkipVerify: true  # For testing with self-signed certs
```

**With CA Certificate Verification:**
```yaml
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "redis-cluster.traefik.svc.cluster.local:6380"
      redisUsername: "admin"
      redisPassword: "traefik"
      clusterMode: true
      tlsEnabled: true
      tlsCABundle: |
        -----BEGIN CERTIFICATE-----
        [Your CA certificate content here]
        -----END CERTIFICATE-----
```

**How it works:**
- When `tlsEnabled: true`, the plugin establishes TLS connections using Go's `crypto/tls` package
- `tlsInsecureSkipVerify: true` disables certificate verification (useful for testing)
- `tlsCABundle` provides a custom CA certificate for verification
- Works with both single-node and cluster Redis deployments
- Standard TLS port for Redis is 6380 (plain text is 6379)

**⚠️ Security Notes:**
- Always use `tlsInsecureSkipVerify: false` in production
- Provide `tlsCABundle` when using self-signed certificates
- Ensure Redis/Valkey is configured with valid TLS certificates
- Use proper certificate management (cert-manager, Vault, etc.)

## Redis Data Management

**Data Structure:**
```bash
# Pattern: uuid:{orgID}:allowed
# Type: SET
# Members: Individual IPs or CIDR blocks

# Individual IPs
SADD "uuid:org-123:allowed" "10.0.1.5"
SADD "uuid:org-123:allowed" "192.168.1.100"

# CIDR blocks
SADD "uuid:org-123:allowed" "10.42.0.0/16"
SADD "uuid:org-123:allowed" "192.168.0.0/24"

# Mixed (both IPs and CIDRs)
SADD "uuid:org-456:allowed" "172.16.50.100" "10.0.0.0/8" "192.168.1.0/24"
```

**Managing Allowlists:**
```bash
# Add individual IPs to allowlist
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SADD "uuid:org-123:allowed" "10.0.1.5" "192.168.1.100"

# Add CIDR blocks to allowlist
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SADD "uuid:org-123:allowed" "10.42.0.0/16" "192.168.0.0/24"

# Add mixed (IPs and CIDRs)
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SADD "uuid:org-123:allowed" "172.16.50.100" "10.0.0.0/8"

# View all allowed IPs/CIDRs
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SMEMBERS "uuid:org-123:allowed"

# Check if specific IP is allowed (exact match only)
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SISMEMBER "uuid:org-123:allowed" "10.0.1.5"

# Remove IP or CIDR from allowlist
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  SREM "uuid:org-123:allowed" "10.0.1.5"

# Remove entire allowlist
kubectl exec -n traefik redis-0 -- redis-cli --user default -a password \
  DEL "uuid:org-123:allowed"
```

## How It Works

1. **JWT middleware** extracts org IDs from token and sets `X-Org` header
2. **Plugin extracts** client IP from `X-Forwarded-For`, `X-Real-IP`, or `RemoteAddr`
3. **For each org ID**:
   - Check in-memory cache
   - Check if Redis key `uuid:{orgID}:allowed` exists
   - **Fast path**: Use `SISMEMBER` to check exact IP match
   - **CIDR path**: If no exact match, fetch all members with `SMEMBERS` and check CIDR ranges
4. **Decision**:
   - ✅ Allow if ANY org permits the IP (exact match or CIDR range)
   - ✅ Allow if org not in Redis (fail-open)
   - ✅ Allow if Redis unavailable (fail-open)
   - ❌ Deny if org exists but IP not allowed

**Logging:**
- No logs for successful requests
- ERROR for denied requests
- WARNING for Redis failures (fail-open)

## Version History

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
