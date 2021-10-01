package models

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
)

type User struct {
	ID       string `json:"id" db:"id"`
	Username string `json:"username" db:"username"`
	Password string `json:"password" db:"password"`
}

type UserModel struct {
	DB *sqlx.DB
}

func (m *UserModel) UserExists(query string) bool {
	var result string
	err := m.DB.Get(&result, "select username from user where username = ? limit 1", query)
	if err == sql.ErrNoRows {
		return false
	} else if err != nil {
		log.Fatalln(err)
	}
	return true
}

func (m *UserModel) GetUserByUsername(query string) (*User, error) {
	if !m.UserExists(query) {
		return nil, fmt.Errorf("The user: %s doesn't exist", query)
	}
	result := []User{}
	stmt := "select id, username, password from user where username = ?"
	err := m.DB.Select(&result, stmt, query)
	if err != nil {
		return nil, err
	}
	return &result[0], nil
}

func (m *UserModel) GetUserByID(query string) (*User, error) {
	result := []User{}
	stmt := "select id, username, password from user where id = ?"
	err := m.DB.Select(&result, stmt, query)
	if err != nil {
		return nil, err
	}
	return &result[0], nil
}

func (m *UserModel) CreateUser(user *User) error {
	stmt := "insert into user (id, username, password) values (?, ?, ?)"
	_, err := m.DB.Exec(stmt, user.ID, user.Username, user.Password)
	return err
}
