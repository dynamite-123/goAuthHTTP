package middleware

import (
	"context"
	"fmt"
	"goAuthHTTP/pkg/utils"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware validates JWT tokens and adds user context
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for certain paths
		skipPaths := map[string]bool{
			"/api/auth/register": true,
			"/api/auth/login":    true,
			"/api/auth/google":   true,
			"/health":            true,
		}

		if skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"Authorization token unavailable"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		tokenStr = strings.TrimSpace(tokenStr)

		// Check if token is blacklisted (user has logged out)
		isBlacklisted := utils.JwtStore.IsBlacklisted(tokenStr)
		if isBlacklisted {
			http.Error(w, `{"error":"Token has been revoked (logged out)"}`, http.StatusUnauthorized)
			return
		}

		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			fmt.Println("ERROR: JWT_SECRET is not set")
			http.Error(w, `{"error":"JWT_SECRET not configured"}`, http.StatusInternalServerError)
			return
		}

		parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				fmt.Printf("ERROR: Invalid signing method: %v\n", token.Method)
				return nil, fmt.Errorf("invalid signing method")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil {
			fmt.Printf("ERROR: Token parsing failed: %v\n", err)
			http.Error(w, fmt.Sprintf(`{"error":"Token parsing failed: %v"}`, err), http.StatusUnauthorized)
			return
		}

		if !parsedToken.Valid {
			fmt.Println("ERROR: Token is not valid")
			http.Error(w, `{"error":"Token is not valid"}`, http.StatusUnauthorized)
			return
		}

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			fmt.Println("ERROR: Cannot parse claims")
			http.Error(w, `{"error":"Cannot parse claims"}`, http.StatusUnauthorized)
			return
		}

		role, ok := claims["role"].(string)
		if !ok {
			fmt.Printf("ERROR: Role claim missing or invalid. Claims: %v\n", claims)
			http.Error(w, `{"error":"Role claim missing"}`, http.StatusUnauthorized)
			return
		}

		userId, ok := claims["uid"].(string)
		if !ok {
			fmt.Printf("ERROR: UID claim missing or invalid. Claims: %v\n", claims)
			http.Error(w, `{"error":"UID claim missing"}`, http.StatusUnauthorized)
			return
		}

		username, ok := claims["user"].(string)
		if !ok {
			fmt.Printf("ERROR: User claim missing or invalid. Claims: %v\n", claims)
			http.Error(w, `{"error":"User claim missing"}`, http.StatusUnauthorized)
			return
		}

		expiresAtF64, ok := claims["exp"].(float64)
		if !ok {
			fmt.Printf("ERROR: Expiry claim missing or invalid. Claims: %v\n", claims)
			http.Error(w, `{"error":"Expiry claim missing"}`, http.StatusUnauthorized)
			return
		}
		expiresAtInt := int64(expiresAtF64)

		fmt.Printf("Authentication successful for user: %s (role: %s)\n", username, role)

		// Add user information to request context
		ctx := context.WithValue(r.Context(), utils.ContextKey("role"), role)
		ctx = context.WithValue(ctx, utils.ContextKey("userId"), userId)
		ctx = context.WithValue(ctx, utils.ContextKey("username"), username)
		ctx = context.WithValue(ctx, utils.ContextKey("expiresAt"), expiresAtInt)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CORS middleware to handle Cross-Origin Resource Sharing
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
