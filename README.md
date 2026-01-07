# OrgID Auth Plugin

A Traefik middleware plugin for organization-based IP authentication using Redis/Valkey as the backend.

## Features

- **IP Allowlist Enforcement**: Validates client IPs against organization-specific allowlists stored in Redis/Valkey
- **Multi-Organization Support**: Extracts organization IDs from JWT claims and checks if ANY organization allows the client IP
- **Fail-Open Policy**: Allows requests when Redis is unavailable or organization doesn't exist in the database
- **Connection Pooling**: Efficient Redis connection management with automatic stale connection cleanup
- **In-Memory Caching**: Reduces Redis load with configurable TTL-based caching
- **Clean Logging**: Only logs errors and warnings, not successful requests

## Installation

### Helm Installation

Add the plugin to your Traefik Helm installation:

```bash
helm upgrade traefik traefik/traefik -n traefik --wait \
  --reuse-values \
  --set experimental.plugins.orgidauthplugin.moduleName=github.com/carlosvillanua/orgidauthplugin \
  --set experimental.plugins.orgidauthplugin.version=v0.1.1 \
  --set experimental.plugins.orgidauthplugin.settings.useUnsafe=true \
  --set 'additionalArguments[0]=--hub.pluginRegistry.sources.github.baseModuleName=github.com' \
  --set 'additionalArguments[1]=--hub.pluginRegistry.sources.github.github.token=YOUR_GITHUB_TOKEN'
```

### Static Configuration

Add to your `traefik.yml` or command-line arguments:

```yaml
experimental:
  plugins:
    orgidauthplugin:
      moduleName: github.com/carlosvillanua/orgidauthplugin
      version: v0.1.1
```

## Middleware Configuration

### Kubernetes CRD

Create a middleware resource:

```yaml
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: orgid-auth
  namespace: apps
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "valkey-redis-master.traefik.svc.cluster.local:6379"
      redisPassword: "your-redis-password"
      orgHeader: "X-Org"
      poolSize: 10
      maxConnIdleTime: "5m"
      poolWaitTimeout: "2s"
      cacheTTL: "30s"
      cacheMaxSize: 1000
```

### Apply Middleware to Route

```yaml
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: my-app-route
  namespace: apps
spec:
  entryPoints:
    - web
  routes:
    - kind: Rule
      match: Host(`myapp.example.com`)
      services:
        - name: my-app-svc
          port: 8000
      middlewares:
        - name: jwt-authentication  # JWT middleware must come first
        - name: orgid-auth          # Then IP validation
```

## Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `redisAddr` | string | `valkey-redis-master.traefik.svc.cluster.local:6379` | Redis/Valkey server address |
| `redisPassword` | string | `traefik` | Redis authentication password |
| `orgHeader` | string | `X-Org` | HTTP header containing organization IDs from JWT middleware |
| `poolSize` | int | `10` | Maximum number of Redis connections in pool |
| `maxConnIdleTime` | duration | `5m` | Maximum idle time before connection is closed |
| `poolWaitTimeout` | duration | `2s` | Maximum wait time for available connection |
| `cacheTTL` | duration | `30s` | Cache entry time-to-live |
| `cacheMaxSize` | int | `1000` | Maximum number of cached entries |

## Redis Data Structure

The plugin expects organization IP allowlists to be stored in Redis as hash keys:

```bash
# Key pattern: uuid:{orgID}:{suffix}
# Field: ips
# Value: space-separated list of allowed IPs

# Example:
HSET "uuid:org-123:prod" ips "10.0.1.5 192.168.1.100 203.0.113.50"
```

### Managing IP Allowlists

```bash
# Add IPs for an organization
kubectl exec -n traefik redis-master-0 -- redis-cli -a password \
  HSET "uuid:org-123:prod" ips "10.0.1.5 192.168.1.100"

# View allowed IPs
kubectl exec -n traefik redis-master-0 -- redis-cli -a password \
  HGET "uuid:org-123:prod" ips

# Remove organization
kubectl exec -n traefik redis-master-0 -- redis-cli -a password \
  DEL "uuid:org-123:prod"
```

## How It Works

1. **JWT Middleware**: Must run before this plugin to extract organization IDs and set them in the `X-Org` header (configurable)
2. **IP Extraction**: Plugin extracts client IP from `X-Forwarded-For`, `X-Real-IP`, or `RemoteAddr`
3. **Organization Check**: For each organization in the header:
   - Check in-memory cache first
   - Query Redis for `uuid:{orgID}:*` keys
   - Check if client IP exists in the allowlist
4. **Decision**:
   - **Allow** if ANY organization allows the IP
   - **Allow** if organization doesn't exist in Redis (fail-open)
   - **Allow** if Redis is unavailable (fail-open)
   - **Deny** if organization exists but IP is not in allowlist

## Fail-Open Behavior

The plugin implements a fail-open policy for resilience:

- ✅ **Redis Connection Failed**: Allow request (logged as WARNING)
- ✅ **Organization Not in Redis**: Allow request (silent, expected behavior)
- ❌ **Organization Exists + IP Not Allowed**: Deny request (logged as ERROR)

## Logging

The plugin uses minimal logging to reduce noise:

- **No logs** for successful requests (Traefik access logs already capture this)
- **ERROR** logs for denied requests with reason
- **WARNING** logs for Redis connection issues (fail-open scenarios)

## Example Full Setup

```yaml
# 1. JWT Middleware - extracts org IDs
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: jwt-authentication
  namespace: apps
spec:
  plugin:
    jwt:
      signingSecret: your-jwt-secret
      forwardHeaders:
        X-Org: "https://api.example.com/organisations"

# 2. IP Auth Middleware - validates IPs
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: orgid-auth
  namespace: apps
spec:
  plugin:
    orgidauthplugin:
      redisAddr: "redis-master.default.svc.cluster.local:6379"
      redisPassword: "secret"
      orgHeader: "X-Org"

# 3. Route - applies both middlewares
---
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
        - name: jwt-authentication  # First: validate JWT & extract orgs
        - name: orgid-auth          # Second: validate IP for orgs
```

## Performance

- **Cache Hit**: ~100μs (in-memory lookup)
- **Cache Miss**: ~2-5ms (Redis query + IP validation)
- **Connection Pool**: Reuses connections to minimize overhead
- **Caching**: Reduces Redis load by 95%+ for repeated requests

## Version History

- **v0.1.1** (2026-01-07): Configuration parsing fix
  - Fixed duration field parsing from YAML strings
  - Supports duration formats like "5m", "30s", "2s" in configuration
  - Improved struct architecture for cleaner code

- **v0.1.0** (2026-01-07): Initial release
  - Organization-based IP authentication
  - Redis/Valkey backend support
  - Connection pooling and caching
  - Fail-open policy implementation

## License

MIT
