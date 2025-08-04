# Test JWT Tokens for JWT Organization Redirect Middleware

This document provides sample JWT tokens for testing the middleware functionality.

## Sample JWT Tokens

### Engineering Organization Token
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcmdfbmFtZSI6ImVuZ2luZWVyaW5nIiwic3ViIjoidGVzdC11c2VyQGFsdHVzLmNvdXBhbmcubmV0IiwiaWF0IjoxNzIyNzI3ODEwLCJleHAiOjE3MjI3MzE0MTAsImlzcyI6ImFsdHVzLW9hdXRoIiwiYXVkIjoiZ3JhZmFuYSJ9.dummy-signature
```

**Decoded Payload:**
```json
{
  "org_name": "engineering",
  "sub": "test-user@example.com",
  "iat": 1722727810,
  "exp": 1722731410,
  "iss": "altus-oauth",
  "aud": "grafana"
}
```

### Marketing Organization Token
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcmdfbmFtZSI6Im1hcmtldGluZyIsInN1YiI6Im1hcmtldGluZy11c2VyQGFsdHVzLmNvdXBhbmcubmV0IiwiaWF0IjoxNzIyNzI3ODEwLCJleHAiOjE3MjI3MzE0MTAsImlzcyI6ImFsdHVzLW9hdXRoIiwiYXVkIjoiZ3JhZmFuYSJ9.dummy-signature
```

**Decoded Payload:**
```json
{
  "org_name": "marketing",
  "sub": "marketing-user@example.com",
  "iat": 1722727810,
  "exp": 1722731410,
  "iss": "altus-oauth",
  "aud": "grafana"
}
```

### Sales Organization Token
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcmdfbmFtZSI6InNhbGVzIiwic3ViIjoic2FsZXMtdXNlckBhbHR1cy5jb3VwYW5nLm5ldCIsImlhdCI6MTcyMjcyNzgxMCwiZXhwIjoxNzIyNzMxNDEwLCJpc3MiOiJhbHR1cy1vYXV0aCIsImF1ZCI6ImdyYWZhbmEifQ.dummy-signature
```

**Decoded Payload:**
```json
{
  "org_name": "sales",
  "sub": "sales-user@example.com",
  "iat": 1722727810,
  "exp": 1722731410,
  "iss": "altus-oauth",
  "aud": "grafana"
}
```

### Token Without Organization (should pass through)
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJub29yZy11c2VyQGFsdHVzLmNvdXBhbmcubmV0IiwiaWF0IjoxNzIyNzI3ODEwLCJleHAiOjE3MjI3MzE0MTAsImlzcyI6ImFsdHVzLW9hdXRoIiwiYXVkIjoiZ3JhZmFuYSJ9.dummy-signature
```

**Decoded Payload:**
```json
{
  "sub": "noorg-user@example.com",
  "iat": 1722727810,
  "exp": 1722731410,
  "iss": "altus-oauth",
  "aud": "grafana"
}
```

## Testing Commands

### Test with Cookie
```bash
# Should redirect to OAuth with organization=engineering
curl -b "access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcmdfbmFtZSI6ImVuZ2luZWVyaW5nIiwic3ViIjoidGVzdC11c2VyQGFsdHVzLmNvdXBhbmcubmV0IiwiaWF0IjoxNzIyNzI3ODEwLCJleHAiOjE3MjI3MzE0MTAsImlzcyI6ImFsdHVzLW9hdXRoIiwiYXVkIjoiZ3JhZmFuYSJ9.dummy-signature" \
     -i http://localhost/auth
```

### Test with Authorization Header
```bash
# Should redirect to OAuth with organization=marketing
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcmdfbmFtZSI6Im1hcmtldGluZyIsInN1YiI6Im1hcmtldGluZy11c2VyQGFsdHVzLmNvdXBhbmcubmV0IiwiaWF0IjoxNzIyNzI3ODEwLCJleHAiOjE3MjI3MzE0MTAsImlzcyI6ImFsdHVzLW9hdXRoIiwiYXVkIjoiZ3JhZmFuYSJ9.dummy-signature" \
     -i http://localhost/oauth?response_type=code&client_id=grafana
```

### Test with Query Parameter
```bash
# Should redirect to OAuth with organization=sales
curl -i "http://localhost/auth?access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcmdfbmFtZSI6InNhbGVzIiwic3ViIjoic2FsZXMtdXNlckBhbHR1cy5jb3VwYW5nLm5ldCIsImlhdCI6MTcyMjcyNzgxMCwiZXhwIjoxNzIyNzMxNDEwLCJpc3MiOiJhbHR1cy1vYXV0aCIsImF1ZCI6ImdyYWZhbmEifQ.dummy-signature"
```

### Test without Token (should redirect to login)
```bash
# Should redirect to /login?return_url=%2Fauth
curl -i http://localhost/auth
```

### Test Non-Protected Path (should pass through)
```bash
# Should return 200 OK
curl -i http://localhost/public
```

### Test Invalid Token (should redirect to login)
```bash
# Should redirect to /login
curl -b "access_token=invalid.jwt.token" -i http://localhost/auth
```

## JWT Token Generation Script

Use this Node.js script to generate your own test tokens:

```javascript
const jwt = require('jsonwebtoken');

const secretKey = 'test-secret-key';

function generateToken(orgName, user) {
  const payload = {
    org_name: orgName,
    sub: user,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
    iss: 'altus-oauth',
    aud: 'grafana'
  };
  
  return jwt.sign(payload, secretKey);
}

// Generate tokens
console.log('Engineering Token:');
console.log(generateToken('engineering', 'test-user@example.com'));

console.log('\nMarketing Token:');
console.log(generateToken('marketing', 'marketing-user@example.com'));

console.log('\nSales Token:');
console.log(generateToken('sales', 'sales-user@example.com'));
```

## Expected Behavior

| Scenario | Token Present | org_name in JWT | Expected Result |
|----------|---------------|-----------------|-----------------|
| Protected path + valid token + org_name | ✓ | ✓ | Add organization param and continue |
| Protected path + valid token + no org_name | ✓ | ✗ | Pass through without modification |
| Protected path + no token | ✗ | N/A | Redirect to login endpoint |
| Protected path + invalid token | ✓ | N/A | Redirect to login endpoint |
| Non-protected path | Any | Any | Pass through without processing |
| OAuth request + valid token + org_name | ✓ | ✓ | Redirect to OAuth with organization |

## Debugging

Enable debug logging in the middleware configuration:

```yaml
jwt-org-redirect:
  debug: true
```

This will log:
- Request processing decisions
- Token extraction attempts
- JWT parsing results
- Organization parameter injection
- OAuth redirect decisions
- Error conditions and fallbacks
