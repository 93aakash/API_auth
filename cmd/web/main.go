package main

import (
	"log"
	"net/http"
	"os"

	"github.com/93aakash/jwt_auth/handlers"
	"github.com/93aakash/jwt_auth/models"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	db, err := sqlx.Connect("sqlite3", "jwt_auth.db")
	if err != nil {
		log.Fatalln(err)
	}

	env := &handlers.Env{
		Users:  models.UserModel{DB: db},
		JWTKey: os.Getenv("JWT_SECRET_KEY"),
	}
	http.HandleFunc("/home", env.HandleHome)
	http.HandleFunc("/login", env.HandleLogin)
	http.HandleFunc("/refresh", env.HandleRefresh)
	http.HandleFunc("/register", env.HandleRegister)

	log.Fatal(http.ListenAndServe(":8000", nil))
}
