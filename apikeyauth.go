// Package apikeyauth is a Traefik middleware plugin that lets a request through
// only when a header carries one of the configured API keys.
package apikeyauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
)

const hashPrefix = "sha256:"

// Config is the middleware configuration.
type Config struct {
	// HeaderName is the request header that carries the key.
	HeaderName string `json:"headerName,omitempty"`
	// Scheme, when set, expects the header value to be "<Scheme> <key>",
	// for example "Bearer" with the Authorization header.
	Scheme string `json:"scheme,omitempty"`
	// Keys are the accepted keys, in plain text or as "sha256:<hex digest>".
	// List several to rotate keys without downtime.
	Keys []string `json:"keys,omitempty"`
	// RemoveHeader strips the key header before the request is forwarded.
	RemoveHeader bool `json:"removeHeader,omitempty"`
	// ExcludedPaths skip the check for these exact paths.
	ExcludedPaths []string `json:"excludedPaths,omitempty"`
	// ExcludedPathPrefixes skip the check for these paths and everything below
	// them: "/public" matches "/public" and "/public/x", not "/publicity".
	ExcludedPathPrefixes []string `json:"excludedPathPrefixes,omitempty"`
	// ExcludedMethods skip the check for these methods, such as OPTIONS for
	// CORS preflight requests.
	ExcludedMethods []string `json:"excludedMethods,omitempty"`
	// Response is sent when the key is missing or wrong.
	Response Response `json:"response,omitempty"`
}

// Response is the response sent to rejected requests.
type Response struct {
	// StatusCode defaults to 401.
	StatusCode int `json:"statusCode,omitempty"`
	// Body defaults to the status text, for example "Unauthorized".
	Body string `json:"body,omitempty"`
	// ContentType defaults to "text/plain; charset=utf-8".
	ContentType string `json:"contentType,omitempty"`
	// Headers are added to the response, for example WWW-Authenticate.
	Headers map[string]string `json:"headers,omitempty"`
}

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{
		HeaderName: "X-API-Key",
		Response: Response{
			StatusCode:  http.StatusUnauthorized,
			ContentType: "text/plain; charset=utf-8",
		},
	}
}

// APIKeyAuth is the middleware.
type APIKeyAuth struct {
	next             http.Handler
	header           string
	scheme           string
	digests          [][]byte
	removeHeader     bool
	excludedPaths    map[string]bool
	excludedPrefixes []string
	excludedMethods  map[string]bool
	response         Response
	body             []byte
}

// New validates the configuration and returns the middleware. Every invalid
// setting is an error, so Traefik never serves a route behind a broken check.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	header := strings.TrimSpace(config.HeaderName)
	if header == "" || strings.ContainsAny(header, " \t\r\n:") {
		return nil, fmt.Errorf("invalid headerName %q", config.HeaderName)
	}

	scheme := strings.TrimSpace(config.Scheme)
	if strings.ContainsAny(scheme, " \t\r\n") {
		return nil, fmt.Errorf("invalid scheme %q", config.Scheme)
	}

	digests, err := parseKeys(config.Keys)
	if err != nil {
		return nil, err
	}

	excludedPaths := make(map[string]bool, len(config.ExcludedPaths))
	for _, p := range config.ExcludedPaths {
		if p = strings.TrimSpace(p); p != "" {
			excludedPaths[cleanPath(p)] = true
		}
	}

	var excludedPrefixes []string
	for _, p := range config.ExcludedPathPrefixes {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		p = cleanPath(p)
		if p == "/" {
			return nil, errors.New(`excludedPathPrefixes must not contain "/", which would skip every request`)
		}
		excludedPrefixes = append(excludedPrefixes, p)
	}

	excludedMethods := make(map[string]bool, len(config.ExcludedMethods))
	for _, m := range config.ExcludedMethods {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			excludedMethods[m] = true
		}
	}

	response := config.Response
	if response.StatusCode == 0 {
		response.StatusCode = http.StatusUnauthorized
	}
	if response.StatusCode < 300 || response.StatusCode > 599 {
		return nil, fmt.Errorf("response.statusCode %d must be between 300 and 599", response.StatusCode)
	}
	if response.Body == "" {
		response.Body = http.StatusText(response.StatusCode) + "\n"
	}
	if response.ContentType == "" {
		response.ContentType = "text/plain; charset=utf-8"
	}

	return &APIKeyAuth{
		next:             next,
		header:           http.CanonicalHeaderKey(header),
		scheme:           scheme,
		digests:          digests,
		removeHeader:     config.RemoveHeader,
		excludedPaths:    excludedPaths,
		excludedPrefixes: excludedPrefixes,
		excludedMethods:  excludedMethods,
		response:         response,
		body:             []byte(response.Body),
	}, nil
}

// parseKeys turns every key into its SHA-256 digest. Surrounding whitespace is
// trimmed, since a header value cannot carry it and secret files often end in
// a newline; a key that is empty after trimming is an error.
func parseKeys(keys []string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one key is required")
	}

	digests := make([][]byte, 0, len(keys))
	for i, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("keys[%d] is empty", i)
		}

		if strings.HasPrefix(key, hashPrefix) {
			digest, err := hex.DecodeString(strings.TrimPrefix(key, hashPrefix))
			if err != nil || len(digest) != sha256.Size {
				return nil, fmt.Errorf("keys[%d] is not a valid %s<64 hex characters> digest", i, hashPrefix)
			}
			digests = append(digests, digest)
			continue
		}

		sum := sha256.Sum256([]byte(key))
		digests = append(digests, sum[:])
	}

	return digests, nil
}

func (a *APIKeyAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !a.excluded(req) && !a.authorized(req.Header.Values(a.header)) {
		a.reject(rw)
		return
	}

	if a.removeHeader {
		req.Header.Del(a.header)
	}

	a.next.ServeHTTP(rw, req)
}

// authorized reports whether the header was sent exactly once with one of the
// keys. Every digest is compared, in constant time.
func (a *APIKeyAuth) authorized(values []string) bool {
	if len(values) != 1 {
		return false
	}

	key := strings.TrimSpace(values[0])
	if a.scheme != "" {
		scheme, rest, found := strings.Cut(key, " ")
		if !found || !strings.EqualFold(scheme, a.scheme) {
			return false
		}
		key = strings.TrimSpace(rest)
	}
	if key == "" {
		return false
	}

	sum := sha256.Sum256([]byte(key))
	match := 0
	for _, digest := range a.digests {
		match |= subtle.ConstantTimeCompare(sum[:], digest)
	}

	return match == 1
}

func (a *APIKeyAuth) excluded(req *http.Request) bool {
	if a.excludedMethods[req.Method] {
		return true
	}
	if len(a.excludedPaths) == 0 && len(a.excludedPrefixes) == 0 {
		return false
	}

	p := cleanPath(req.URL.Path)
	if a.excludedPaths[p] {
		return true
	}
	for _, prefix := range a.excludedPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}

	return false
}

func (a *APIKeyAuth) reject(rw http.ResponseWriter) {
	header := rw.Header()
	header.Set("Content-Type", a.response.ContentType)
	for name, value := range a.response.Headers {
		header.Set(name, value)
	}

	rw.WriteHeader(a.response.StatusCode)
	_, _ = rw.Write(a.body)
}

// cleanPath resolves "." and ".." segments, so "/public/../admin" is matched as
// "/admin", the path a backend is likely to serve.
func cleanPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	return path.Clean(p)
}
