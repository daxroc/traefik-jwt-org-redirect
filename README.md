# JWT Organization Redirect Middleware

A Traefik middleware that extracts organization information from JWT tokens and automatically redirects OAuth requests with the correct organization parameter, enabling seamless multi-organization authentication for Grafana and other OAuth-enabled services.

## Features

- **JWT Token Extraction**: Supports multiple token sources (cookies, headers, query parameters)
- **Organization Parameter Injection**: Automatically adds organization parameter to OAuth requests
- **Configurable Protected Paths**: Define which paths require JWT processing
- **Fallback Handling**: Graceful handling of missing or invalid tokens
- **OAuth Integration**: Direct integration with OAuth providers
- **Debug Logging**: Comprehensive logging for troubleshooting
- **Health Monitoring**: Built-in health check endpoint

## Configuration

### Basic Configuration

```yaml
# Traefik dynamic configuration
http:
  middlewares:
    jwt-org-redirect:
      plugin:
        jwt-org-redirect:
          redirectEndpoint: "/login"
          protectedPaths:
            - "/auth"
            - "/oauth"
          organizationParam: "organization"
          tokenSources:
            - "cookie"
            - "header"
            - "query"
          cookieName: "access_token"
          headerName: "Authorization"
          queryParam: "access_token"
          debug: false
```

### Advanced Configuration

```yaml
http:
  middlewares:
    jwt-org-redirect:
      plugin:
        jwt-org-redirect:
          redirectEndpoint: "/login"
          protectedPaths:
            - "/auth"
            - "/oauth"
            - "/grafana/login"
          oauthEndpoint: "https://oauth.example.com/authorize"
          organizationParam: "organization"
          tokenSources:
            - "cookie"
            - "header"
          cookieName: "access_token"
          headerName: "Authorization"
          jwtSecretKey: "your-jwt-secret-key"
          debug: true
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `redirectEndpoint` | string | `/login` | Endpoint to redirect to when access_token is missing |
| `protectedPaths` | []string | `["/auth"]` | Paths that require JWT processing |
| `oauthEndpoint` | string | - | OAuth provider endpoint for organization-aware redirects |
| `organizationParam` | string | `organization` | Name of the organization parameter to add |
| `tokenSources` | []string | `["cookie", "header", "query"]` | Sources to search for JWT tokens |
| `cookieName` | string | `access_token` | Name of the cookie containing JWT token |
| `headerName` | string | `Authorization` | Name of the header containing JWT token |
| `queryParam` | string | `access_token` | Name of the query parameter containing JWT token |
| `jwtSecretKey` | string | - | Secret key for JWT validation (optional) |
| `debug` | bool | `false` | Enable debug logging |

## Usage Examples

### Grafana OAuth Integration

```yaml
# Traefik configuration for Grafana with JWT organization redirect
http:
  routers:
    grafana:
      rule: "Host(`grafana.example.com`)"
      middlewares:
        - "jwt-org-redirect"
      service: "grafana"
      
  middlewares:
    jwt-org-redirect:
      plugin:
        jwt-org-redirect:
          redirectEndpoint: "/login"
          protectedPaths:
            - "/login/generic_oauth"
            - "/oauth"
          oauthEndpoint: "https://oauth.example.com/authorize"
          organizationParam: "organization"
          cookieName: "grafana_session"
          debug: false
          
  services:
    grafana:
      loadBalancer:
        servers:
          - url: "http://grafana:3000"
```

### Multi-Path Protection

```yaml
http:
  middlewares:
    jwt-org-redirect:
      plugin:
        jwt-org-redirect:
          protectedPaths:
            - "/auth"
            - "/oauth"
            - "/login"
            - "/grafana"
            - "/api/auth"
          tokenSources:
            - "cookie"
            - "header"
          cookieName: "session_token"
          headerName: "X-Auth-Token"
```

## JWT Token Format

The middleware expects JWT tokens to contain an `org_name` claim:

```json
{
  "sub": "user@example.com",
  "org_name": "engineering",
  "iat": 1640995200,
  "exp": 1640998800
}
```

## Request Flow

1. **Request Interception**: Middleware intercepts requests to protected paths
2. **Token Extraction**: Searches for JWT tokens in configured sources (cookies, headers, query params)
3. **Token Validation**: Parses JWT and extracts `org_name` claim
4. **Organization Injection**: Adds organization parameter to request
5. **OAuth Redirect**: If OAuth endpoint is configured, redirects with organization parameter
6. **Fallback Handling**: Redirects to login endpoint if token is missing or invalid

## Error Handling

- **Missing Token**: Redirects to configured login endpoint with return URL
- **Invalid JWT**: Logs error and redirects to login endpoint
- **Missing org_name**: Passes request through without modification
- **OAuth Redirect Failure**: Falls back to normal request processing

## Monitoring and Debugging

### Debug Logging

Enable debug logging to troubleshoot token extraction and organization parsing:

```yaml
jwt-org-redirect:
  debug: true
```

Debug logs include:
- Request path processing
- Token source detection
- JWT parsing results
- Organization parameter injection
- OAuth redirect decisions

### Health Check

The middleware provides a health check endpoint for monitoring:

```bash
curl http://localhost/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-08-04T00:56:50Z",
  "middleware": "jwt-org-redirect",
  "config": {
    "protected_paths": ["/auth", "/oauth"],
    "redirect_endpoint": "/login",
    "organization_param": "organization",
    "token_sources": ["cookie", "header", "query"]
  }
}
```

## Security Considerations

- **JWT Validation**: Optional JWT signature validation with `jwtSecretKey`
- **Secure Token Handling**: Tokens are not logged in production mode
- **Timing Attack Protection**: Constant-time string comparison for sensitive operations
- **Input Validation**: Proper URL encoding and parameter sanitization

## Installation

### As Traefik Plugin

1. Add the plugin to your Traefik configuration:

```yaml
experimental:
  plugins:
    jwt-org-redirect:
      moduleName: "github.com/daxroc/traefik-jwt-org-redirect"
      version: "v1.0.0"
```

2. Configure the middleware in your dynamic configuration
3. Apply to routes that require JWT organization processing

### Development Setup

```bash
# Clone the repository
git clone https://github.com/daxroc/traefik-jwt-org-redirect.git
cd jwt-org-redirect

# Install dependencies
go mod tidy

# Run tests
go test ./...

# Build the plugin
go build -o jwt-org-redirect main.go
```

## Testing

### Unit Tests

```bash
go test -v ./...
```

### Integration Testing

```bash
# Test with sample JWT token
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
     http://localhost/auth

# Test without token (should redirect to login)
curl -i http://localhost/auth

# Test with cookie
curl -b "access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
     http://localhost/oauth
```

## Troubleshooting

### Common Issues

1. **Token Not Found**
   - Verify token source configuration matches your application
   - Check cookie names, header names, and query parameter names
   - Enable debug logging to see token extraction attempts

2. **JWT Parsing Errors**
   - Ensure JWT tokens are properly formatted
   - Verify `org_name` claim exists in the token
   - Check JWT signature validation if `jwtSecretKey` is configured

3. **Redirect Loops**
   - Ensure login endpoint is not in `protectedPaths`
   - Verify OAuth endpoint configuration
   - Check return URL parameter handling

### Debug Commands

```bash
# Check middleware configuration
curl http://localhost/health

# Test token extraction
curl -H "Authorization: Bearer <token>" -v http://localhost/auth

# Verify organization parameter injection
curl -b "access_token=<token>" -v "http://localhost/oauth?debug=1"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues and questions:
- Create an issue in the GitHub repository
- Contact the Platform Engineering team
- Check the RFE documentation: `docs-src/internal-team/planning/rfe/rfe-2025-07-31-001.md`
