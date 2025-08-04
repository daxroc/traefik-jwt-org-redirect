// Package jwt_org_redirect implements a Traefik middleware that extracts organization
// information from JWT tokens and redirects OAuth requests with the correct organization parameter.
package traefik_jwt_org_redirect

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds the middleware configuration
type Config struct {
	// RedirectEndpoint is the endpoint to redirect to when access_token is missing
	RedirectEndpoint string `json:"redirectEndpoint,omitempty"`

	// ProtectedPaths are the paths that require JWT processing (e.g., ["/auth", "/login"])
	ProtectedPaths []string `json:"protectedPaths,omitempty"`

	// OAuthEndpoint is the OAuth provider endpoint to redirect to with organization parameter
	OAuthEndpoint string `json:"oauthEndpoint,omitempty"`

	// JWTSecretKey is the secret key for JWT validation (optional, for validation)
	JWTSecretKey string `json:"jwtSecretKey,omitempty"`

	// OrganizationParam is the name of the organization parameter to add (default: "organization")
	OrganizationParam string `json:"organizationParam,omitempty"`

	// TokenSources defines where to look for JWT tokens (cookie, header, query)
	TokenSources []string `json:"tokenSources,omitempty"`

	// CookieName is the name of the cookie containing the JWT token
	CookieName string `json:"cookieName,omitempty"`

	// HeaderName is the name of the header containing the JWT token
	HeaderName string `json:"headerName,omitempty"`

	// QueryParam is the name of the query parameter containing the JWT token
	QueryParam string `json:"queryParam,omitempty"`

	// Debug enables debug logging
	Debug bool `json:"debug,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		RedirectEndpoint:  "/login",
		ProtectedPaths:    []string{"/auth"},
		OrganizationParam: "organization",
		TokenSources:      []string{"cookie", "header", "query"},
		CookieName:        "access_token",
		HeaderName:        "Authorization",
		QueryParam:        "access_token",
		Debug:             false,
	}
}

// JWTOrgRedirect holds the middleware instance
type JWTOrgRedirect struct {
	next   http.Handler
	config *Config
	name   string
}

// JWTClaims represents the JWT token claims structure
type JWTClaims struct {
	OrgName string `json:"org_name"`
	jwt.RegisteredClaims
}

// New creates a new JWTOrgRedirect middleware instance
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedirectEndpoint == "" {
		config.RedirectEndpoint = "/login"
	}

	if len(config.ProtectedPaths) == 0 {
		config.ProtectedPaths = []string{"/auth"}
	}

	if config.OrganizationParam == "" {
		config.OrganizationParam = "organization"
	}

	if len(config.TokenSources) == 0 {
		config.TokenSources = []string{"cookie", "header", "query"}
	}

	if config.CookieName == "" {
		config.CookieName = "access_token"
	}

	if config.HeaderName == "" {
		config.HeaderName = "Authorization"
	}

	if config.QueryParam == "" {
		config.QueryParam = "access_token"
	}

	return &JWTOrgRedirect{
		next:   next,
		config: config,
		name:   name,
	}, nil
}

// ServeHTTP implements the middleware logic
func (j *JWTOrgRedirect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if j.config.Debug {
		log.Printf("[%s] Processing request: %s %s", j.name, req.Method, req.URL.Path)
	}

	// Check if this is a protected path
	if !j.isProtectedPath(req.URL.Path) {
		if j.config.Debug {
			log.Printf("[%s] Path %s is not protected, passing through", j.name, req.URL.Path)
		}
		j.next.ServeHTTP(rw, req)
		return
	}

	// Extract JWT token from request
	token := j.extractToken(req)
	if token == "" {
		if j.config.Debug {
			log.Printf("[%s] No access token found, redirecting to %s", j.name, j.config.RedirectEndpoint)
		}
		j.redirectToLogin(rw, req)
		return
	}

	// Parse JWT and extract organization
	orgName, err := j.parseOrgFromJWT(token)
	if err != nil {
		if j.config.Debug {
			log.Printf("[%s] Failed to parse JWT: %v, redirecting to login", j.name, err)
		}
		j.redirectToLogin(rw, req)
		return
	}

	if orgName == "" {
		if j.config.Debug {
			log.Printf("[%s] No org_name found in JWT, passing through", j.name)
		}
		j.next.ServeHTTP(rw, req)
		return
	}

	// Add organization parameter to request
	j.addOrganizationParam(req, orgName)

	if j.config.Debug {
		log.Printf("[%s] Added organization parameter: %s=%s", j.name, j.config.OrganizationParam, orgName)
	}

	// If OAuth endpoint is configured and this is an OAuth request, redirect with organization
	if j.config.OAuthEndpoint != "" && j.isOAuthRequest(req) {
		j.redirectToOAuth(rw, req, orgName)
		return
	}

	j.next.ServeHTTP(rw, req)
}

// isProtectedPath checks if the current path requires JWT processing
func (j *JWTOrgRedirect) isProtectedPath(path string) bool {
	for _, protectedPath := range j.config.ProtectedPaths {
		if strings.HasPrefix(path, protectedPath) {
			return true
		}
	}
	return false
}

// extractToken extracts JWT token from various sources (cookie, header, query parameter)
func (j *JWTOrgRedirect) extractToken(req *http.Request) string {
	for _, source := range j.config.TokenSources {
		var token string

		switch source {
		case "cookie":
			if cookie, err := req.Cookie(j.config.CookieName); err == nil {
				token = cookie.Value
			}
		case "header":
			authHeader := req.Header.Get(j.config.HeaderName)
			if authHeader != "" {
				// Handle "Bearer <token>" format
				if strings.HasPrefix(authHeader, "Bearer ") {
					token = strings.TrimPrefix(authHeader, "Bearer ")
				} else {
					token = authHeader
				}
			}
		case "query":
			token = req.URL.Query().Get(j.config.QueryParam)
		}

		if token != "" {
			if j.config.Debug {
				log.Printf("[%s] Found token in %s", j.name, source)
			}
			return token
		}
	}

	return ""
}

// parseOrgFromJWT parses the JWT token and extracts the org_name claim
func (j *JWTOrgRedirect) parseOrgFromJWT(tokenString string) (string, error) {
	// Parse token without verification first to extract claims
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return "", fmt.Errorf("invalid JWT claims structure")
	}

	// If JWT secret is provided, validate the token
	if j.config.JWTSecretKey != "" {
		validatedToken, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(j.config.JWTSecretKey), nil
		})

		if err != nil {
			return "", fmt.Errorf("JWT validation failed: %w", err)
		}

		if !validatedToken.Valid {
			return "", fmt.Errorf("invalid JWT token")
		}

		validatedClaims, ok := validatedToken.Claims.(*JWTClaims)
		if !ok {
			return "", fmt.Errorf("invalid validated JWT claims")
		}

		claims = validatedClaims
	}

	return claims.OrgName, nil
}

// addOrganizationParam adds the organization parameter to the request
func (j *JWTOrgRedirect) addOrganizationParam(req *http.Request, orgName string) {
	// Add to query parameters
	query := req.URL.Query()
	query.Set(j.config.OrganizationParam, orgName)
	req.URL.RawQuery = query.Encode()

	// Also add as form value for POST requests
	if req.Method == "POST" && req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		if err := req.ParseForm(); err == nil {
			req.Form.Set(j.config.OrganizationParam, orgName)
		}
	}
}

// redirectToLogin redirects the user to the configured login endpoint
func (j *JWTOrgRedirect) redirectToLogin(rw http.ResponseWriter, req *http.Request) {
	// Preserve the original URL as a return parameter
	returnURL := req.URL.String()
	redirectURL := j.config.RedirectEndpoint

	if strings.Contains(redirectURL, "?") {
		redirectURL += "&return_url=" + url.QueryEscape(returnURL)
	} else {
		redirectURL += "?return_url=" + url.QueryEscape(returnURL)
	}

	http.Redirect(rw, req, redirectURL, http.StatusTemporaryRedirect)
}

// isOAuthRequest checks if this is an OAuth authorization request
func (j *JWTOrgRedirect) isOAuthRequest(req *http.Request) bool {
	// Check for common OAuth parameters
	query := req.URL.Query()
	return query.Get("response_type") != "" || query.Get("client_id") != "" || strings.Contains(req.URL.Path, "oauth") || strings.Contains(req.URL.Path, "authorize")
}

// redirectToOAuth redirects to OAuth provider with organization parameter
func (j *JWTOrgRedirect) redirectToOAuth(rw http.ResponseWriter, req *http.Request, orgName string) {
	oauthURL, err := url.Parse(j.config.OAuthEndpoint)
	if err != nil {
		if j.config.Debug {
			log.Printf("[%s] Invalid OAuth endpoint: %v", j.name, err)
		}
		j.next.ServeHTTP(rw, req)
		return
	}

	// Copy existing query parameters
	query := oauthURL.Query()
	for key, values := range req.URL.Query() {
		for _, value := range values {
			query.Add(key, value)
		}
	}

	// Add organization parameter
	query.Set(j.config.OrganizationParam, orgName)
	oauthURL.RawQuery = query.Encode()

	if j.config.Debug {
		log.Printf("[%s] Redirecting to OAuth with organization: %s", j.name, oauthURL.String())
	}

	http.Redirect(rw, req, oauthURL.String(), http.StatusTemporaryRedirect)
}

// Health check endpoint for monitoring
func (j *JWTOrgRedirect) healthCheck(rw http.ResponseWriter, req *http.Request) {
	response := map[string]interface{}{
		"status":     "healthy",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"middleware": j.name,
		"config": map[string]interface{}{
			"protected_paths":    j.config.ProtectedPaths,
			"redirect_endpoint":  j.config.RedirectEndpoint,
			"organization_param": j.config.OrganizationParam,
			"token_sources":      j.config.TokenSources,
		},
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	json.NewEncoder(rw).Encode(response)
}

// secureCompare performs constant-time string comparison to prevent timing attacks
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// main function for plugin compilation
func main() {
	// This main function is required for Go plugin compilation
	// The actual plugin entry point is the New function
}
