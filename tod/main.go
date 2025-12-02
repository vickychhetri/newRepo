package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	db           *gorm.DB
	jwtSecretKey []byte
	tokenTTL     = time.Hour * 24
)

type User struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Username string `gorm:"uniqueIndex;not null" json:"username"`
	Password string `gorm:"not null" json:"-"`
	Tasks    []Task `json:"tasks, omitempty"`
}

type Task struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Title       string    `gorm:"not null" json:"title"`
	Description string    `json:"description"`
	Completed   bool      `gorm:"default:false" json:"completed"`
	CreatedAt   time.Time `json:"created_at"`
	UpdateddAt  time.Time `json:"updated_at"`
	UserId      uint      `json:"user_id"`
}

func hashPassword(pass string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	return string(b), err
}

func checkPassword(hash, pass string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
}
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Username == "" && req.Password == "" {
		http.Error(w, "username and password required.", http.StatusBadRequest)
		return
	}
	h, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "unable to hash password", http.StatusBadRequest)
		return
	}

	user := User{
		Username: req.Username,
		Password: h,
	}

	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "unable to create user", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"id": user.ID, "username": user.Username})
}

func LoginHandler(w http.ResponseWriter, r *http.Response) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	err := checkPassword(user.Password, req.Password)
	if err != nil {
		http.Error(w, "Wrong Password", http.StatusBadRequest)
		return
	}

	token, err := generateToken(user.ID)

}

func main() {
	s := os.Getenv("TODI_JWT_SECRET")
	if s == "" {
		log.Println("Env TODI_JWT_SECRET not set ")
		s = "Please-change-this"
	}

	jwtSecretKey = []byte(s)

	var err error
	db, err = gorm.Open(sqlite.Open("todi.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("err")
	}
	db.AutoMigrate(&User{}, &Task{})
	r := mux.NewRouter()
	r.HandleFunc("/signup", SignupHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")

}
