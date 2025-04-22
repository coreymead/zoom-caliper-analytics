package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/corey/zoom-caliper/internal/types"
	"github.com/corey/zoom-caliper/internal/zoom"
	"github.com/gin-gonic/gin"
)

type Config struct {
	ZoomWebhookSecret string
	OAuthConfig       *zoom.OAuthConfig
	TokenStore        zoom.TokenStore
	CaliperClient     types.CaliperClient
	EventStore        types.EventStore
	Port              int
	WebhookPath       string
	ListenAddr        string
	CertFile          string
	KeyFile           string
}

type Server struct {
	config *Config
	router *gin.Engine
	zoomClient *zoom.Client
}

func NewServer(config *Config) *Server {
	if config.Port == 0 {
		config.Port = 8080
	}

	router := gin.Default()
	server := &Server{
		config: config,
		router: router,
		zoomClient: zoom.NewClient(config.TokenStore),
	}

	// Set up routes
	router.POST("/webhook/zoom", server.handleWebhook)
	router.GET("/oauth/authorize", server.handleOAuthAuthorize)
	router.GET("/oauth/callback", server.handleOAuthCallback)
	router.GET("/user", server.handleUser)
	router.GET("/caliper-events.json", server.handleCaliperEvents)

	return server
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	log.Printf("Starting server on %s", addr)
	
	// Check if TLS certificates are provided
	if s.config.CertFile != "" && s.config.KeyFile != "" {
		log.Printf("TLS certificates provided, starting HTTPS server")
		
		// Create TLS configuration
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		
		server := &http.Server{
			Addr:      addr,
			Handler:   s.router,
			TLSConfig: tlsConfig,
		}
		
		return server.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
	}
	
	// Fall back to HTTP if no certificates
	return s.router.Run(addr)
}

func (s *Server) handleWebhook(c *gin.Context) {
	// Log the request
	log.Println("Webhook request received")
	
	// Get raw body for debugging
	body, err := c.GetRawData()
	if err != nil {
		log.Printf("Error reading body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}
	
	// Don't log the entire body in production - it could contain sensitive data
	bodyLength := len(body)
	log.Printf("Raw body length: %d bytes", bodyLength)
	
	// Restore body for further processing
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	// For development, make verification optional based on env var
	skipVerification := os.Getenv("SKIP_WEBHOOK_VERIFICATION") == "true"
	if !skipVerification {
		// Pass both the request and body to verification
		signature := c.Request.Header.Get("x-zm-signature")
		timestamp := c.Request.Header.Get("x-zm-request-timestamp")
		
		// Directly verify signature without re-reading the body
		if err := zoom.ValidateSignature(signature, timestamp, body, s.config.ZoomWebhookSecret); err != nil {
			log.Printf("Webhook signature verification failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Invalid webhook signature: %v", err)})
			return
		}
		log.Println("Webhook signature verified successfully")
	} else {
		log.Println("Webhook signature verification skipped")
	}

	// Re-restore body for the handler (since it will be consumed)
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	
	// Process webhook
	zoom.HandleWebhook(c, s.zoomClient, s.config.TokenStore, s.config.EventStore)
}

func (s *Server) handleOAuthAuthorize(c *gin.Context) {
	url := s.config.OAuthConfig.AuthCodeURL()
	log.Printf("Redirecting to Zoom OAuth URL: %s", url)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (s *Server) handleOAuthCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing authorization code"})
		return
	}

	token, err := s.config.OAuthConfig.Exchange(code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange authorization code"})
		return
	}

	if err := s.config.TokenStore.SaveToken(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleUser(c *gin.Context) {
	// Check if we have a valid token
	token, err := s.config.TokenStore.GetToken()
	if err != nil {
		log.Printf("Error getting token: %v", err)
		c.Redirect(http.StatusFound, "/oauth/authorize")
		return
	}

	if token.IsExpired() {
		log.Println("Token is expired, redirecting to authorization")
		c.Redirect(http.StatusFound, "/oauth/authorize")
		return
	}

	// Get user information
	user, err := s.zoomClient.GetMe()
	if err != nil {
		log.Printf("Error getting user information: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user information"})
		return
	}

	// Respond with user information
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, fmt.Sprintf(`
	<html>
		<head>
			<title>Zoom Caliper - User Information</title>
			<style>
				body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
				h1 { color: #2D8CFF; }
				.user-card { 
					border: 1px solid #ddd; 
					border-radius: 8px; 
					padding: 20px; 
					margin-top: 20px;
					max-width: 600px;
					box-shadow: 0 2px 4px rgba(0,0,0,0.1);
				}
				.label { font-weight: bold; color: #444; }
				.auth-status { 
					padding: 8px 16px; 
					border-radius: 20px; 
					display: inline-block; 
					margin-top: 20px;
					background-color: #4CAF50;
					color: white;
				}
			</style>
		</head>
		<body>
			<h1>Zoom Caliper Integration</h1>
			<div class="user-card">
				<h2>Authenticated User</h2>
				<p><span class="label">Name:</span> %s %s</p>
				<p><span class="label">Email:</span> %s</p>
				<p><span class="label">User ID:</span> %s</p>
				<p><span class="label">Role:</span> %s</p>
				<p><span class="label">Status:</span> %s</p>
				<div class="auth-status">✓ Successfully Authenticated with Zoom</div>
			</div>
		</body>
	</html>
	`, user.FirstName, user.LastName, user.Email, user.ID, user.RoleName, user.Status))
}

func (s *Server) handleCaliperEvents(c *gin.Context) {
	events := s.config.EventStore.GetEvents()
	c.JSON(http.StatusOK, events)
} 