# API Key Auth for Traefik

A [Traefik](https://traefik.io/) middleware plugin that lets a request through only when a header carries one of your API keys. Everything else gets a response you choose, such as `401 Unauthorized`.

- Any header, with an optional scheme: `X-API-Key: <key>` or `Authorization: Bearer <key>`.
- Several keys at once, so you can rotate them without downtime.
- Keys in plain text, as SHA-256 digests (`sha256:<hex>`), or read from a Kubernetes Secret.
- Exact-path, path-prefix and method exclusions for health checks and CORS preflights.
- A configurable rejection: status, body, content type and headers.
- Keys are compared as SHA-256 digests in constant time.
- Fails closed: an invalid configuration stops Traefik from serving the route rather than letting requests through.

## Install

Declare the plugin in Traefik's static configuration:

```yaml
experimental:
  plugins:
    apikeyauth:
      moduleName: github.com/firecrawl/traefik-api-key-auth
      version: v0.1.0
```

Traefik loads plugins at startup, so restart it after adding this.

## Configure

### Kubernetes

Traefik's Kubernetes CRD provider replaces `urn:k8s:secret:<secret>:<key>` with that key of a Secret in the Middleware's namespace, so the key never appears in the Middleware itself:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: api-key
  namespace: my-app
spec:
  plugin:
    apikeyauth:
      headerName: X-API-Key
      keys:
        - urn:k8s:secret:my-app-secrets:API_KEY
      excludedPaths:
        - /health
```

Attach it to an `IngressRoute` under `middlewares`, or to an `Ingress` with the annotation `traefik.ingress.kubernetes.io/router.middlewares: my-app-api-key@kubernetescrd`.

### File provider

```yaml
http:
  middlewares:
    api-key:
      plugin:
        apikeyauth:
          headerName: Authorization
          scheme: Bearer
          keys:
            - sha256:b16481f1ada69c0032fb6624d311dc4b3ed6dbb5a2becc4dd3d82f31014ee6e8
          response:
            statusCode: 401
            contentType: application/json
            body: '{"error":"unauthorized"}'
            headers:
              WWW-Authenticate: Bearer
```

### Docker labels

```yaml
labels:
  - traefik.http.routers.my-app.middlewares=api-key
  - traefik.http.middlewares.api-key.plugin.apikeyauth.headerName=X-API-Key
  - traefik.http.middlewares.api-key.plugin.apikeyauth.keys=sha256:b16481f1ada69c0032fb6624d311dc4b3ed6dbb5a2becc4dd3d82f31014ee6e8
```

Labels can be read by anyone with access to the Docker API, so use a `sha256:` digest here rather than the key itself.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `headerName` | `X-API-Key` | Request header that carries the key. |
| `scheme` | none | When set, the header value must be `<scheme> <key>`, for example `Bearer`. Matched case-insensitively. |
| `keys` | required | Accepted keys, in plain text or as `sha256:<64 hex characters>`. At least one, none empty. |
| `removeHeader` | `false` | Strip the key header before forwarding the request. |
| `excludedPaths` | none | Exact paths that skip the check, such as `/health`. |
| `excludedPathPrefixes` | none | Paths that skip the check together with everything below them. `/public` matches `/public` and `/public/x`, not `/publicity`. |
| `excludedMethods` | none | Methods that skip the check, such as `OPTIONS`. |
| `response.statusCode` | `401` | Status of the rejection, from 300 to 599. |
| `response.body` | the status text | Body of the rejection. |
| `response.contentType` | `text/plain; charset=utf-8` | Content type of the rejection. Set it together with `body`. |
| `response.headers` | none | Extra headers on the rejection, such as `WWW-Authenticate` or `Location`. |

## Behaviour

- **Fails closed.** Missing or empty keys, a malformed digest or an invalid status make the middleware fail to build, and Traefik does not serve routes that use it. In Kubernetes the same happens when a `urn:k8s:secret` reference cannot be resolved.
- **Whitespace.** Surrounding whitespace is trimmed from keys and header values. A header value cannot carry it anyway, and secret files often end in a newline.
- **One header only.** A request that sends the header more than once is rejected.
- **Exclusions** are matched after resolving `.` and `..` segments, so `/health/../admin` is checked as `/admin`. Requests that match an excluded method reach your backend without any check, so make sure the backend does nothing sensitive for them.
- **Forwarding.** The header reaches your backend unchanged unless `removeHeader` is set.

## Generating keys

```sh
# A new key
openssl rand -hex 32

# Its digest, for the sha256: form
printf '%s' "$KEY" | sha256sum
```

## Development

Traefik runs plugins in the [Yaegi](https://github.com/traefik/yaegi) Go interpreter, which provides the Go 1.22 standard library, so the module targets Go 1.22 and has no dependencies. `go vet ./...` reports any use of newer standard library APIs.

To try local changes, use Traefik's [local plugin mode](https://plugins.traefik.io/install): place the repository at `./plugins-local/src/github.com/firecrawl/traefik-api-key-auth` next to the Traefik binary and declare it with:

```yaml
experimental:
  localPlugins:
    apikeyauth:
      moduleName: github.com/firecrawl/traefik-api-key-auth
```

## License

[MIT](LICENSE)
