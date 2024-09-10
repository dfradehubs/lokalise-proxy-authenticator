package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	utils "lokalise-proxy-authenticator/internal"
)

func main() {

	// Get the target URL from the environment
	targetURL := os.Getenv("LOKALISE_URL")
	if targetURL == "" {
		log.Println("LOKALISE_URL not set, using default target https://app.lokalise.com")
		targetURL = "https://app.lokalise.com"
	}

	// Get the port to listen on from the environment
	listerPort := os.Getenv("LISTEN_PORT")
	if listerPort == "" {
		log.Println("LISTEN_PORT not set, using default port 8080")
		listerPort = "8080"
	}

	login_post_path := os.Getenv("LOGIN_POST_PATH")
	if login_post_path == "" {
		log.Println("LOGIN_POST_PATH not set, using default path /login/signin")
		login_post_path = "/login/signin"
	}

	// Parse the target URL
	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Invalid LOKALISE_URL: %v", err)
	}

	// Start the proxy server
	http.HandleFunc("/", utils.ProxyHandler(target, login_post_path))
	log.Println("Starting lokalise-proxy-authenticator server on :" + listerPort)
	log.Fatal(http.ListenAndServe(":"+listerPort, nil))
}
