package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Login payload json to send to /login/signin
type LoginPayload struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	JoinProject string `json:"joinProject"`
	Lang        string `json:"lang"`
}

// ExtractCredentialsFromAuth decodes the base64 string from the Authorization header
func ExtractCredentialsFromAuth(authHeader string) (string, string, error) {

	// Checks the format of the Authorization header, must start with "Basic"
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", fmt.Errorf("Authorization header must start with 'Basic'")
	}

	// Removes the "Basic " prefix
	encoded := strings.TrimPrefix(authHeader, "Basic ")

	// Decodes the base64 string
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode base64: %v", err)
	}

	// Split user and password
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return "", "", fmt.Errorf("invalid credentials format")
	}

	email := credentials[0]
	password := credentials[1]

	return email, password, nil
}

// getInitialCookie requests / to get the initial cookie
func GetInitialCookie(target *url.URL) (string, string, error) {

	// Build GET request to /
	req, err := http.NewRequest("GET", target.String(), nil)
	if err != nil {
		return "", "", err
	}

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("failed to login, status: %d", resp.StatusCode)
	}

	// Read Set-Cookie headers to get the inital cookie
	setCookie := resp.Header["Set-Cookie"]
	if len(setCookie) == 0 {
		return "", "", fmt.Errorf("no Set-Cookie header in response")
	}

	// Extract csrf_token and PHPSESSID from Set-Cookie headers
	var csrfToken, phpSessID string
	for _, cookie := range setCookie {
		if strings.Contains(cookie, "csrf_token") {
			csrfToken = extractCookieValue("csrf_token", cookie)
		}
		if strings.Contains(cookie, "PHPSESSID") {
			phpSessID = extractCookieValue("PHPSESSID", cookie)
		}
	}

	// Check if the cookies were extracted
	if csrfToken == "" || phpSessID == "" {
		return "", "", fmt.Errorf("failed to extract required cookies")
	}

	// Format the cookies for future requests
	return fmt.Sprintf("csrf_token=%s; PHPSESSID=%s", csrfToken, phpSessID), csrfToken, nil
}

// getLoginCookie requests LOGIN_POST_PATH to get the authenticated cookie
func GetLoginCookie(target *url.URL, email, password string, cookie string, csrf_token string, login_post_path string) (string, error) {

	// Build the URL to /login/signin
	loginURL := target.ResolveReference(&url.URL{Path: login_post_path})

	// Get the login payload
	payload := LoginPayload{
		Email:       email,
		Password:    password,
		JoinProject: "",
		Lang:        "",
	}

	// Convert the payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Creates a POST request to /login/signin with the payload and needed headers
	req, err := http.NewRequest("POST", loginURL.String(), bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", target.Scheme+"://"+target.Host)
	req.Header.Set("Origin", target.Scheme+"://"+target.Host)
	req.Header.Set("Cookie", cookie)
	req.Header.Set("X-Csrf-Token", csrf_token)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to login, status: %d", resp.StatusCode)
	}

	// Read Set-Cookie headers to get the authenticated cookie
	setCookie := resp.Header["Set-Cookie"]
	if len(setCookie) == 0 {
		return "", fmt.Errorf("no Set-Cookie header in response")
	}

	// Extract csrf_token and PHPSESSID from Set-Cookie headers
	var csrfToken, phpSessID string
	for _, cookie := range setCookie {
		if strings.Contains(cookie, "csrf_token") {
			csrfToken = extractCookieValue("csrf_token", cookie)
		}
		if strings.Contains(cookie, "PHPSESSID") {
			phpSessID = extractCookieValue("PHPSESSID", cookie)
		}
	}

	// Check if the cookies were extracted
	if csrfToken == "" || phpSessID == "" {
		return "", fmt.Errorf("failed to extract required cookies")
	}

	// Format the cookies for future requests
	return fmt.Sprintf("csrf_token=%s; PHPSESSID=%s", csrfToken, phpSessID), nil
}

// extractCookieValue extract the value of a cookie from a raw cookie string
func extractCookieValue(name, rawCookie string) string {
	parts := strings.Split(rawCookie, ";")
	for _, part := range parts {
		if strings.Contains(part, name) {
			return strings.Split(part, "=")[1]
		}
	}
	return ""
}

// ProxyHandler manages input requests and redirects them to the target server
func ProxyHandler(target *url.URL, login_post_path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Checks if the request has a cookie and a CSRF token
		cookie := r.Header.Get("Cookie")
		csrf_token := r.Header.Get("x-csrf-token")
		if cookie == "" || csrf_token == "" {

			// Check if the request has an Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header missing", http.StatusUnauthorized)
				return
			}

			// Gets the email and password from the Authorization header
			email, password, err := ExtractCredentialsFromAuth(authHeader)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Gets the initial cookie and CSRF token which uses to get the authenticated cookie
			cookie, csrf_token, err = GetInitialCookie(target)
			if err != nil {
				http.Error(w, "Error fetching initial login cookie: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Gets the authenticated cookie
			cookie, err = GetLoginCookie(target, email, password, cookie, csrf_token, login_post_path)
			if err != nil {
				http.Error(w, "Error fetching login cookie: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Adds the authenticated cookie to the request
			r.Header.Set("Cookie", cookie)
		}

		// Redirects the request to the target server
		proxyRequest(target, w, r)

	}
}

// proxyRequest redirects the request to the target server
func proxyRequest(target *url.URL, w http.ResponseWriter, r *http.Request) {

	// Creates a new request to the target server
	proxyReq, err := http.NewRequest(r.Method, target.ResolveReference(r.URL).String(), r.Body)
	if err != nil {
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy the original request headers
	proxyReq.Header = r.Header

	// Send the request to the target server
	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Error forwarding request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy the response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Copy the response status code
	w.WriteHeader(resp.StatusCode)

	// Copy the response body
	io.Copy(w, resp.Body)
}
