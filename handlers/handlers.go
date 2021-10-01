package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/crypto/bcrypt"

	"github.com/93aakash/jwt_auth/models"
)

type Env struct {
	Users  models.UserModel
	JWTKey string
}

func (env *Env) HandleHome(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		msg := "Content-Type header is not application/json"
		http.Error(w, msg, http.StatusUnsupportedMediaType)
		return
	}
	token, err := jwt.ParseRequest(
		r,
		jwt.WithValidate(true),
		jwt.WithVerify(jwa.HS256, []byte(env.JWTKey)),
	)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid token")
		return
	}

	user_id := token.Subject()
	user, err := env.Users.GetUserByID(user_id)

	log.Println("Access token verified successfully")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(
		w,
		`{"response": "Hey %s! Thanks for dropping by."}`,
		user.Username,
	)
}

func (env *Env) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No POST")
		return
	}

	user := models.User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		log.Println(err)
		http.Error(
			w,
			http.StatusText(http.StatusBadRequest),
			http.StatusInternalServerError,
		)
		return
	}

	userDB, err := env.Users.GetUserByUsername(user.Username)

	if err != nil || !ComparePasswords(userDB.Password, user.Password) {
		w.WriteHeader(http.StatusForbidden)
		log.Println(err)
		fmt.Fprintln(w, "Wrong credentials")
		return
	}

	accessToken, err := CreateAccessToken(userDB, []byte(env.JWTKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to send token")
		log.Printf("Token Signing error: %v\n", err)
		return
	}
	refreshToken, err := CreateRefreshToken(userDB, []byte(env.JWTKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to send token")
		log.Printf("Token Signing error: %v\n", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := `{"access_token": "%s", "refresh_token": "%s"}`
	fmt.Fprintf(w, response, accessToken, refreshToken)
}

func (env *Env) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No POST")
		return
	}

	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(
			w,
			http.StatusText(http.StatusBadRequest),
			http.StatusInternalServerError,
		)
		return
	}

	token, err := jwt.Parse(
		[]byte(data["refresh_token"]),
		jwt.WithValidate(true),
		jwt.WithVerify(jwa.HS256, []byte(env.JWTKey)),
	)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid token")
		return
	}

	user_id := token.Subject()
	user, err := env.Users.GetUserByID(user_id)

	accessToken, err := CreateAccessToken(user, []byte(env.JWTKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to send token")
		log.Printf("Token Signing error: %v\n", err)
		return
	}
	tokens := models.Token{AccessToken: accessToken}

	log.Println("Refresh token verified successfully")

	response, err := json.Marshal(tokens)
	if err != nil {
		log.Println(err)
		http.Error(
			w,
			http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError,
		)
		return
	}
	fmt.Fprintf(w, string(response))
}

func (env *Env) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No POST")
		return
	}

	user := models.User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		log.Println(err)
		http.Error(
			w,
			http.StatusText(http.StatusBadRequest),
			http.StatusInternalServerError,
		)
		return
	}
	if env.Users.UserExists(user.Username) {
		errMessage := fmt.Sprintf("Username %s already exists", user.Username)
		log.Println(errMessage)
		http.Error(w, errMessage, http.StatusBadRequest)
		return
	}

	user.ID = uuid.New().String()
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to process request")
		log.Println(err)
		return
	}
	user.Password = string(hash)

	err = env.Users.CreateUser(&user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to process request")
		log.Println(err)
		return
	}
	log.Printf("User %s has been created\n", user.Username)

	accessToken, err := CreateAccessToken(&user, []byte(env.JWTKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to send token")
		log.Printf("Token Signing error: %v\n", err)
		return
	}
	refreshToken, err := CreateRefreshToken(&user, []byte(env.JWTKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to send token")
		log.Printf("Token Signing error: %v\n", err)
		return
	}

	tokens := models.Token{AccessToken: accessToken, RefreshToken: refreshToken}

	response, err := json.Marshal(tokens)
	if err != nil {
		log.Println(err)
		http.Error(
			w,
			http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError,
		)
		return
	}
	fmt.Fprintf(w, string(response))
}

func ComparePasswords(hash string, passwd string) bool {
	byteHash := []byte(hash)
	bytePasswd := []byte(passwd)

	err := bcrypt.CompareHashAndPassword(byteHash, bytePasswd)
	if err != nil {
		return false
	}
	return true
}

func CreateAccessToken(user *models.User, JWTKey []byte) (string, error) {
	t := jwt.New()
	t.Set(jwt.ExpirationKey, time.Now().Add(time.Minute*10).Unix())
	t.Set(jwt.IssuedAtKey, time.Now().Unix())
	t.Set(jwt.SubjectKey, user.ID)
	t.Set(`username`, user.Username)

	payload, err := jwt.Sign(t, jwa.HS256, JWTKey)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func CreateRefreshToken(user *models.User, JWTKey []byte) (string, error) {
	t := jwt.New()
	t.Set(jwt.ExpirationKey, time.Now().AddDate(0, 0, 7).Unix())
	t.Set(jwt.SubjectKey, user.ID)

	payload, err := jwt.Sign(t, jwa.HS256, JWTKey)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}
