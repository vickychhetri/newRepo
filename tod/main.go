package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"tod/handler"
	"tod/model"

	"github.com/gorilla/mux"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	s := os.Getenv("TODI_JWT_SECRET")
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

	addr := ":8080"
	fmt.Printf("Server Listening at port:  %s", addr)
	http.ListenAndServe(addr, r)
}
