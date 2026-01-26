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
  --set experimental.plugins.orgidauthplugin.version=v0.1.5
```

**Static Config (`traefik.yml`):**
```yaml
experimental:
  plugins:
    orgidauthplugin:
      moduleName: github.com/carlosvillanua/orgidauthplugin
      version: v0.1.5
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
| `redisPassword` | string | `traefik` | Redis password |
| `orgHeader` | string | `X-Org` | Header containing org IDs (set by JWT middleware) |
| `poolSize` | int | `10` | Max Redis connections |
| `maxConnIdleTime` | duration | `5m` | Max idle time before closing connection |
| `poolWaitTimeout` | duration | `2s` | Max wait for available connection |
| `cacheTTL` | duration | `30s` | Cache entry TTL |
| `cacheMaxSize` | int | `1000` | Max cached entries |
| `clusterMode` | bool | `false` | Enable Redis Cluster support |

## Redis Cluster

For Redis Cluster deployments:

```yaml
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "redis-cluster.default.svc.cluster.local:6379"
      clusterMode: true
      poolSize: 100      # Higher for cluster
      cacheTTL: "1s"     # Lower for faster updates
```

**How it works:**
- Discovers all master nodes via `CLUSTER NODES`
- Queries all nodes with `KEYS` command
- Handles `MOVED` redirects for reading values
- Aggregates results across all shards

**⚠️ Important:** Without `clusterMode: true`, only keys on the connected node are visible, causing fail-open for other orgs.

## Redis Data Management

**Data Structure:**
```bash
# Pattern: uuid:{orgID}:{env}
# Field: ips
# Value: space-separated IPs

HSET "uuid:org-123:prod" ips "10.0.1.5 192.168.1.100"
```

**Managing Allowlists:**
```bash
# Add/update IPs
kubectl exec -n traefik redis-0 -- redis-cli -a password \
  HSET "uuid:org-123:prod" ips "10.0.1.5 192.168.1.100"

# View IPs
kubectl exec -n traefik redis-0 -- redis-cli -a password \
  HGET "uuid:org-123:prod" ips

# Remove org
kubectl exec -n traefik redis-0 -- redis-cli -a password \
  DEL "uuid:org-123:prod"
```

## How It Works

1. **JWT middleware** extracts org IDs from token and sets `X-Org` header
2. **Plugin extracts** client IP from `X-Forwarded-For`, `X-Real-IP`, or `RemoteAddr`
3. **For each org ID**:
   - Check in-memory cache
   - Query Redis for `uuid:{orgID}:*` keys
   - Check if client IP is in allowlist
4. **Decision**:
   - ✅ Allow if ANY org permits the IP
   - ✅ Allow if org not in Redis (fail-open)
   - ✅ Allow if Redis unavailable (fail-open)
   - ❌ Deny if org exists but IP not allowed

**Logging:**
- No logs for successful requests
- ERROR for denied requests
- WARNING for Redis failures (fail-open)

## Version History

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
