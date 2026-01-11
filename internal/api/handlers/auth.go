package handlers

import (
	"encoding/json"
	"goAuthHTTP/internal/repositories/mongodb"
	"goAuthHTTP/pkg/utils"
	"net/http"
	"strings"
	"time"
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
