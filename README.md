# Lokalise Proxy Authenticator

![GitHub go.mod Go version (subdirectory of monorepo)](https://img.shields.io/github/go-mod/go-version/dfradehubs/lokalise-proxy-authenticator)
![GitHub](https://img.shields.io/github/license/dfradehubs/lokalise-proxy-authenticator)

This is a simple proxy responsible for redirecting authenticated requests using the Authorization Basic user:password header to Lokalise, which currently uses CSRF token-based authentication. The proxy handles cases where the user is not authenticated and lacks those headers by generating new ones using the Authorization header and transparently injecting them into the user's browser."

## Features

- **Proxy Handler**: Intercepts HTTP requests and checks for necessary authentication headers and tokens.
- **Cookie and CSRF Token Management**: Automatically retrieves and manages login cookies and CSRF tokens.
- **Authorization Header Support**: Extracts user credentials from the `Authorization` header if cookies and tokens are missing.
- **Forward Requests**: Proxies the request to a target server after successful authentication.

## Requirements

- Go 1.18+
- Target server must support cookie-based authentication with CSRF tokens via Set-Cookie headers.

## Environment Variables

- `LOKALISE_URL`: The URL of the target server to which requests should be proxied (default is `https://app.lokalise.com`)
- `LISTEN_PORT`: The port on which the proxy server will listen (default is `8080`).
- `LOGIN_POST_PATH`: The Login URL where the proxy sends the POST request to get the authenticated CSRF token.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/lokalise-proxy-authenticator.git
   ```

2. Navigate to the project directory:

   ```bash
   cd lokalise-proxy-authenticator
   ```

3. Build the Go binary:

   ```bash
   make build
   ```

## Usage

1. Set the environment variables

    ```bash
    export LOKALISE_URL="https://app.lokalise.com" # Optional, default is https://app.lokalise.com
    export LISTEN_PORT="8080"  # Optional, default is 8080
    export LOGIN_POST_PATH="/login/signin"  # Optional, default is /login/signin
    ```

2. Run the proxy server

   ```bash
   make run
   ```

3. The proxy server will start on the port specified in LISTEN_PORT (default: 8080), and it will forward authenticated requests to the LOKALISE_URL.

## Code Structure

- cmd/main.go: Main file containing the proxy logic.
- internal/utils.go: Contains utility functions for handling authentication, such as:
  - ExtractCredentialsFromAuth: Extracts email and password from the Authorization header.
  - GetInitialCookie: Fetches the initial cookie and CSRF token for the login session.
  - GetLoginCookie: Logs in using the credentials and returns the authenticated cookie.
- Makefile: Useful commands for build, test and run the code.
- Dockerfile: For building the docker image
- charts: Helm chart for the application
- .github: CI/CD tools for github repository.


## Example Request

   ```bash
   curl -X GET http://localhost:8080/your-path \
   -H "Authorization: Basic base64encodedcredentials" \
   ```

If the request lacks the Authorization, Cookie, or CSRF token, the proxy server will attempt to authenticate and retrieve them before forwarding the request.

## License

This project is licensed under the MIT License.
Feel free to replace any placeholders like `yourusername` in the repository URL.