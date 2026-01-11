package handlers

import (
	"encoding/json"
	"goAuthHTTP/internal/models"
	"goAuthHTTP/internal/repositories/mongodb"
	"goAuthHTTP/pkg/utils"
	"net/http"
)

type GoogleLoginRequest struct {
	IdToken string `json:"id_token"`
}

type GoogleLoginResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	User         *models.User `json:"user"`
}

// GoogleLogin handles Google OAuth authentication
func GoogleLogin(w http.ResponseWriter, r *http.Request) {
	var req GoogleLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Verify the Google ID token
	googleUser, err := utils.VerifyGoogleIDToken(r.Context(), req.IdToken)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid Google ID token")
		return
	}

	// Check if user exists by Google ID first
	existingUser, err := mongodb.GetUserByGoogleId(r.Context(), googleUser.Sub)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error checking for existing user")
		return
	}

	var user *models.User

	// If user doesn't exist with this Google ID, check by email
	if existingUser == nil {
		existingUser, err = mongodb.GetUserByEmail(r.Context(), googleUser.Email)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Error checking for existing user by email")
			return
		}

		// If user exists by email but not Google ID, update their Google ID
		if existingUser != nil {
			// Update existing user with Google ID and picture
			err = mongodb.UpdateUserGoogleInfo(r.Context(), existingUser.Id, googleUser.Sub, googleUser.Picture)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "Error updating user with Google information")
				return
			}

			// Update the model with the new Google info for the response
			existingUser.GoogleId = googleUser.Sub
			existingUser.Picture = googleUser.Picture
			user = existingUser
		} else {
			// Create a new user
			newUser, err := mongodb.CreateGoogleUser(r.Context(), googleUser.Email, googleUser.Name, googleUser.Sub, googleUser.Picture)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "Error creating new user")
				return
			}
			user = newUser
		}
	} else {
		// User exists, use their data
		user = existingUser
	}

	// Generate access token (JWT)
	accessToken, err := utils.SignToken(user.Id, user.Username, user.Role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Could not create access token")
		return
	}

	// Generate refresh token (for now, using the same token generation)
	// In a production environment, you'd want a separate refresh token mechanism
	refreshToken, err := utils.SignToken(user.Id, user.Username, user.Role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Could not create refresh token")
		return
	}

	// Don't send password in response
	user.Password = ""

	respondJSON(w, http.StatusOK, GoogleLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	})
}
