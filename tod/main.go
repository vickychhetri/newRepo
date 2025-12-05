package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"tod/handler"
	"tod/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func parseToken(token string) (*model.Claims, error) {
	//check for empty string
	if token == "" {
		return nil, errors.New("empty token")
	}

	token = strings.TrimSpace(token)
	//parse the JWT Token

	//Decode the token
	// Validate signature
	// Validate expiry or other registered fields

	parsed, err := jwt.ParseWithClaims(token, &model.Claims{}, func(token *jwt.Token) (any, error) {
		return model.JwtSecretKey, nil
	})

	//If token is invalid, expired, or signature mismatch → error here.
	if err != nil {
		return nil, err
	}

	// Parsed token contains claims in generic interface.
	//We convert it to your custom Claims struct.
	claims, ok := parsed.Claims.(*model.Claims)

	// Check claims type and token validity
	if !ok || !parsed.Valid {
		//ok == false → claims not convertible to your struct.
		// parsed.Valid == false → signature invalid, expired, malformed, etc.
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Authorization token missing, failed", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(auth, " ")
		if len(parts) != 2 || parts[0] != "bearer" {
			http.Error(w, "Authorization not configure properly, failed", http.StatusUnauthorized)
			return
		}

		cliams, err := parseToken(parts[1])
		if err != nil {
			http.Error(w, "Wrong Toekn,failed"+err.Error(), http.StatusUnauthorized)
			return
		}

		//attach user id to context
		ctx := context.WithValue(r.Context(), "user_id", cliams.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {

	if err := godotenv.Load(); err != nil {
		log.Println("Env TODI_JWT_SECRET not set ")
	}

	s := os.Getenv("KEY")
	if s == "" {
		log.Println("Env TODI_JWT_SECRET not set ")
		s = "Please-change-this"
	}

	model.JwtSecretKey = []byte(s)

	var err error
	dsn := "root:12345678@tcp(127.0.0.1:3306)/tody?charset=utf8mb4&parseTime=True&loc=Local"

	// model.Db, err = gorm.Open(sqlite.Open("todi.db"), &gorm.Config{})
	model.Db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	model.Db.AutoMigrate(&model.User{}, &model.Task{})
	r := mux.NewRouter()
	r.HandleFunc("/signup", handler.SignupHandler).Methods("POST")
	r.HandleFunc("/login", handler.LoginHandler).Methods("POST")

	sub := r.PathPrefix("/task").Subrouter()
	sub.Use(authMiddleware)
	sub.HandleFunc("", handler.CreateTakHandler).Methods("POST")

	addr := ":8080"
	fmt.Printf("Server Listening at port:  %s", addr)
	http.ListenAndServe(addr, r)
}
