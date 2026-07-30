package main

import (
	"fmt"
	"goAuthHTTP/internal/api/handlers"
	"goAuthHTTP/internal/api/middleware"
	"goAuthHTTP/pkg/utils"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func init() {
	// Load .env file if it exists (optional for Docker deployments)
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using environment variables")
	}
}

func main() {
	// Triggers every 2 minutes and cleans up all the expired tokens
	go utils.JwtStore.CleanUpExpiredTokens()

	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Auth routes
	mux.HandleFunc("/api/auth/register", handlers.Register)
	mux.HandleFunc("/api/auth/login", handlers.Login)
	mux.HandleFunc("/api/auth/google", handlers.GoogleLogin)
	mux.HandleFunc("/api/auth/logout", handlers.Logout)
	mux.HandleFunc("/api/auth/change-role", handlers.ChangeRole)
	mux.HandleFunc("/api/auth/verify", handlers.VerifyToken)

	// Apply middleware
	handler := middleware.CORSMiddleware(middleware.AuthMiddleware(mux))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	// Ensure port has colon prefix
	if port[0] != ':' {
		port = ":" + port
	}

	fmt.Printf("HTTP server running on port %s\n", port)
	
	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
