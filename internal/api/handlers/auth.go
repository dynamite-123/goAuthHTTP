package handlers

import (
	"encoding/json"
	"fmt"
	"goAuthHTTP/internal/repositories/mongodb"
	"goAuthHTTP/pkg/utils"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Request/Response structs
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Status bool   `json:"status"`
	Token  string `json:"token"`
}

type ChangeRoleRequest struct {
	Id   string `json:"id"`
	Role string `json:"role"`
}

type ChangeRoleResponse struct {
	Status bool `json:"status"`
}

type LogoutResponse struct {
	Status bool `json:"status"`
}

type VerifyTokenRequest struct {
	Token string `json:"token"`
}

type VerifyTokenResponse struct {
	Status   bool   `json:"status"`
	Id       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Helper functions
func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func respondError(w http.ResponseWriter, code int, message string) {
	respondJSON(w, code, ErrorResponse{Error: message})
}

// Login handles user authentication with username and password
func Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := mongodb.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Incorrect username or password")
		return
	}

	err = utils.VerifyPassword(req.Password, user.Password)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Incorrect username or password")
		return
	}

	tokenString, err := utils.SignToken(user.Id, user.Username, user.Role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Could not create token")
		return
	}

	respondJSON(w, http.StatusOK, LoginResponse{
		Status: true,
		Token:  tokenString,
	})
}

// Register handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
	var req mongodb.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Basic field validation
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	// Check if username already exists
	existingUser, err := mongodb.GetUserByUsername(r.Context(), req.Username)
	if err == nil && existingUser != nil {
		respondError(w, http.StatusConflict, "Username is already taken")
		return
	}

	user, err := mongodb.AddUserToDB(r.Context(), &req)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	tokenString, err := utils.SignToken(user.Id, user.Username, user.Role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Could not create token")
		return
	}

	respondJSON(w, http.StatusOK, LoginResponse{
		Status: true,
		Token:  tokenString,
	})
}

// ChangeRole allows super admins to change user roles (requires authentication)
func ChangeRole(w http.ResponseWriter, r *http.Request) {
	// Check authorization (super admin only)
	err := utils.AuthorizeUser(r.Context(), "super_admin")
	if err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}

	var req ChangeRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err = mongodb.ModifyUserRoleInDB(r.Context(), req.Id, req.Role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, ChangeRoleResponse{
		Status: true,
	})
}

// Logout handles user logout by blacklisting the token
func Logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondError(w, http.StatusUnauthorized, "Unauthorized access")
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimSpace(token)

	if token == "" {
		respondError(w, http.StatusUnauthorized, "Unauthorized access")
		return
	}

	// Get expiry time from context (set by authentication middleware)
	expiryTimeStamp := r.Context().Value(utils.ContextKey("expiresAt"))
	expiryTimeInt, ok := expiryTimeStamp.(int64)
	if !ok {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve token expiry time")
		return
	}

	expiryTime := time.Unix(expiryTimeInt, 0)
	utils.JwtStore.AddToken(token, expiryTime)

	respondJSON(w, http.StatusOK, LogoutResponse{
		Status: true,
	})
}

// VerifyToken validates a JWT token from the request body and returns user details if valid
func VerifyToken(w http.ResponseWriter, r *http.Request) {
	var req VerifyTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		respondError(w, http.StatusBadRequest, "Token is required")
		return
	}

	if utils.JwtStore.IsBlacklisted(req.Token) {
		respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	parsedToken, err := jwt.Parse(req.Token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(jwtSecret), nil
	})
	if err != nil || !parsedToken.Valid {
		respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	claims := parsedToken.Claims.(jwt.MapClaims)
	respondJSON(w, http.StatusOK, VerifyTokenResponse{
		Status:   true,
		Id:       claims["uid"].(string),
		Username: claims["user"].(string),
		Role:     claims["role"].(string),
	})
}

