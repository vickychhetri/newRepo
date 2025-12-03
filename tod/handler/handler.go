package handler

import (
	"encoding/json"
	"net/http"
	"tod/auth"
	"tod/model"
)

// SignupHandler handles user registration
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	// Struct to capture incoming JSON request
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Decode request body into req struct
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Validate that both username and password are provided
	if req.Username == "" && req.Password == "" {
		http.Error(w, "username and password required.", http.StatusBadRequest)
		return
	}

	// Hash the user's password before storing it
	h, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "unable to hash password", http.StatusBadRequest)
		return
	}

	// Create a new user model
	user := model.User{
		Username: req.Username,
		Password: h,
	}

	// Insert the new user into the database
	if err := model.Db.Create(&user).Error; err != nil {
		http.Error(w, "unable to create user", http.StatusBadRequest)
		return
	}

	// Respond with status 201 (Created) and return basic user info
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
	})
}

// LoginHandler authenticates a user and returns a JWT token
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Struct to capture login credentials
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Parse incoming JSON request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Look up the user by username
	var user model.User
	if err := model.Db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Compare provided password with stored hashed password
	err := auth.CheckPassword(user.Password, req.Password)
	if err != nil {
		http.Error(w, "Wrong Password", http.StatusBadRequest)
		return
	}

	// Generate a JWT token for the authenticated user
	token, err := auth.GenerateToken(user.ID)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusBadRequest)
		return
	}

	// Return the token to the client
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}
