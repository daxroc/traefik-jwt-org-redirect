package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// createTestJWT creates a JWT token with the specified org_name for testing
func createTestJWT(orgName string, secretKey string) (string, error) {
	claims := &JWTClaims{
		OrgName: orgName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "test-user",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

// mockHandler is a simple handler for testing
func mockHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func TestJWTOrgRedirect_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		config         *Config
		requestPath    string
		requestMethod  string
		headers        map[string]string
		cookies        []*http.Cookie
		queryParams    map[string]string
		expectedStatus int
		expectedHeader string
		expectedQuery  string
	}{
		{
			name: "Non-protected path should pass through",
			config: &Config{
				ProtectedPaths: []string{"/auth"},
			},
			requestPath:    "/public",
			requestMethod:  "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Protected path without token should redirect to login",
			config: &Config{
				ProtectedPaths:   []string{"/auth"},
				RedirectEndpoint: "/login",
			},
			requestPath:    "/auth",
			requestMethod:  "GET",
			expectedStatus: http.StatusTemporaryRedirect,
			expectedHeader: "/login?return_url=%2Fauth",
		},
		{
			name: "Protected path with valid JWT in cookie should add organization param",
			config: &Config{
				ProtectedPaths:    []string{"/auth"},
				TokenSources:      []string{"cookie"},
				CookieName:        "access_token",
				OrganizationParam: "organization",
			},
			requestPath:   "/auth",
			requestMethod: "GET",
			cookies: []*http.Cookie{
				{
					Name:  "access_token",
					Value: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcmdfbmFtZSI6ImVuZ2luZWVyaW5nIiwic3ViIjoidGVzdC11c2VyIiwiaWF0IjoxNjQwOTk1MjAwLCJleHAiOjE2NDA5OTg4MDB9.dummy",
				},
			},
			expectedStatus: http.StatusOK,
			expectedQuery:  "organization=engineering",
		},
		{
			name: "Invalid JWT should redirect to login",
			config: &Config{
				ProtectedPaths:   []string{"/auth"},
				RedirectEndpoint: "/login",
				TokenSources:     []string{"cookie"},
				CookieName:       "access_token",
			},
			requestPath:   "/auth",
			requestMethod: "GET",
			cookies: []*http.Cookie{
				{
					Name:  "access_token",
					Value: "invalid.jwt.token",
				},
			},
			expectedStatus: http.StatusTemporaryRedirect,
			expectedHeader: "/login?return_url=%2Fauth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create middleware instance
			middleware, err := New(context.Background(), http.HandlerFunc(mockHandler), tt.config, "test-middleware")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			// Create test request
			req := httptest.NewRequest(tt.requestMethod, tt.requestPath, nil)

			// Add query parameters
			if len(tt.queryParams) > 0 {
				q := req.URL.Query()
				for key, value := range tt.queryParams {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()
			}

			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Add cookies
			for _, cookie := range tt.cookies {
				req.AddCookie(cookie)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute middleware
			middleware.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check redirect location
			if tt.expectedHeader != "" {
				location := rr.Header().Get("Location")
				if location != tt.expectedHeader {
					t.Errorf("Expected Location header %q, got %q", tt.expectedHeader, location)
				}
			}

			// Check query parameters (for non-redirect cases)
			if tt.expectedQuery != "" && rr.Code == http.StatusOK {
				if req.URL.RawQuery == "" || req.URL.RawQuery != tt.expectedQuery {
					t.Errorf("Expected query to contain %q, got %q", tt.expectedQuery, req.URL.RawQuery)
				}
			}
		})
	}
}

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	// Test default values
	if config.RedirectEndpoint != "/login" {
		t.Errorf("Expected default RedirectEndpoint '/login', got %q", config.RedirectEndpoint)
	}

	if len(config.ProtectedPaths) != 1 || config.ProtectedPaths[0] != "/auth" {
		t.Errorf("Expected default ProtectedPaths ['/auth'], got %v", config.ProtectedPaths)
	}

	if config.OrganizationParam != "organization" {
		t.Errorf("Expected default OrganizationParam 'organization', got %q", config.OrganizationParam)
	}

	expectedTokenSources := []string{"cookie", "header", "query"}
	if len(config.TokenSources) != len(expectedTokenSources) {
		t.Errorf("Expected TokenSources %v, got %v", expectedTokenSources, config.TokenSources)
	}

	if config.CookieName != "access_token" {
		t.Errorf("Expected default CookieName 'access_token', got %q", config.CookieName)
	}

	if config.HeaderName != "Authorization" {
		t.Errorf("Expected default HeaderName 'Authorization', got %q", config.HeaderName)
	}

	if config.QueryParam != "access_token" {
		t.Errorf("Expected default QueryParam 'access_token', got %q", config.QueryParam)
	}

	if config.Debug != false {
		t.Errorf("Expected default Debug false, got %v", config.Debug)
	}
}
