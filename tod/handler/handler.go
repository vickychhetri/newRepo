package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"tod/auth"
	"tod/model"

	"github.com/gorilla/mux"
)

func GetUserId(r *http.Request) uint {
	v := r.Context().Value("user_id")
	if v == nil {
		return 0
	}

	if i, ok := v.(uint); ok {
		return i
	}

	// sometimes jwt lib gives float64 inside map claims; not here but safe fallback
	if f, ok := v.(float64); ok {
		return uint(f)
	}

	return 0
}

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
		http.Error(w, fmt.Sprintf("%s", err), http.StatusBadRequest)
		return
	}

	// Return the token to the client
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func CreateTakHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	user_id := GetUserId(r)

	task := model.Task{
		Title:       req.Title,
		Description: req.Description,
		CreatedAt:   time.Now(),
		UserId:      user_id,
		Completed:   false,
	}

	if err := model.Db.Create(&task).Error; err != nil {
		http.Error(w, "unable to save task", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Task Created Succesfuuly"})
}

func UpdateTaskHandler(w http.ResponseWriter, r *http.Request) {
	userId := GetUserId(r)
	idStr := mux.Vars(r)["id"]

	var task model.Task
	if err := model.Db.Where("id= ? AND user_id=?", idStr, userId).Find(&task).Error; err != nil {
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}

	var req struct {
		Title       string `json:title`
		Description string `json:description`
		Completed   *bool  `json: completed`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request"+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Description != "" {
		task.Description = req.Description
	}
	if req.Title != "" {
		task.Title = req.Title
	}

	if req.Completed != nil {
		task.Completed = *req.Completed
	}
	task.UpdatedAt = time.Now()
	if err := model.Db.Save(&task).Error; err != nil {
		http.Error(w, "Unable to save Task", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(task)
}

func GetAllTaskHandler(w http.ResponseWriter, r *http.Request) {
	var tasks []model.Task
	var userId = GetUserId(r)

	if err := model.Db.Preload("User").Where("user_id=?", userId).Find(&tasks).Error; err != nil {
		http.Error(w, "unable to get tasks", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
	})
}

func GetSingleTaskHandler(w http.ResponseWriter, r *http.Request) {
	var userId = GetUserId(r)
	var idStr = mux.Vars(r)["id"]
	var task model.Task
	if err := model.Db.Where("id=? AND user_id=? ", idStr, userId).First(&task).Error; err != nil {
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task": task,
	})
}

func DeleteTaskHandler(w http.ResponseWriter, r *http.Request) {
	var userId = GetUserId(r)
	var idStr = mux.Vars(r)["id"]
	var task model.Task
	if err := model.Db.Where("id=? AND user_id=? ", idStr, userId).First(&task).Error; err != nil {
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}

	if err := model.Db.Delete(&task).Error; err != nil {
		http.Error(w, "Unable to delete", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task":    task,
		"message": "deleted succesfully",
	})
}

func CompleteTaskHandler(w http.ResponseWriter, r *http.Request) {
	idStr := mux.Vars(r)["id"]
	userId := GetUserId(r)

	var task model.Task

	if err := model.Db.Where("id=? AND user_id=?", idStr, userId).First(&task).Error; err != nil {
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}
	message := ""
	if task.Completed {
		task.Completed = false
		message = "task marked not-completed"

	} else {
		task.Completed = true
		message = "task marked completed succesfully"
	}

	if err := model.Db.Save(&task).Error; err != nil {
		http.Error(w, "unable to mark completed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": message,
	})
}
