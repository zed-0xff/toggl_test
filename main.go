package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var secretKey = []byte("your-secret-key")

func main() {
	http.HandleFunc("/sign", signHandler)
	http.HandleFunc("/verify", verifyHandler)

	fmt.Println("Listening on :8080...")
	http.ListenAndServe(":8080", nil)
}

func init() {
	// Initialize the database
	var err error
	db, err = sql.Open("sqlite3", "test-signer.db")
	if err != nil {
		panic(err)
	}

	// Create the table if it does not exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS signatures (
			signature TEXT PRIMARY KEY,
			user TEXT,
			questions TEXT,
			answers TEXT,
			timestamp TIMESTAMP
		);
	`)
	if err != nil {
		panic(err)
	}
}

type SignData struct {
	Username  string
	Questions []string
	Answers   []string
	Timestamp time.Time
}

func (sd *SignData) Sign(secretKey []byte) (string, error) {
	// Serialize SignData to JSON
	dataJSON, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}

	// Sign the JSON data
	signature, err := signString(string(dataJSON), secretKey)
	if err != nil {
		return "", err
	}

	return signature, nil
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		UserJwt   string
		Questions []string
		Answers   []string
	}

	// Parse JSON request
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Parse JWT to get the username
	token, err := jwt.Parse(requestData.UserJwt, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		http.Error(w, "Error parsing JWT", http.StatusInternalServerError)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	username, ok := claims["username"].(string)
	if !ok {
		http.Error(w, "Username not found in JWT claims", http.StatusUnauthorized)
		return
	}

	// Create SignData from requestData
	signData := &SignData{
		Username:  username,
		Questions: requestData.Questions,
		Answers:   requestData.Answers,
		Timestamp: time.Now(),
	}

	// Sign
	signature, err := signData.Sign(secretKey)
	if err != nil {
		http.Error(w, "Error signing", http.StatusInternalServerError)
		return
	}

	// Store the signature in the database
	_, err = db.Exec(`
		INSERT INTO signatures (user, signature, questions, answers, timestamp)
		VALUES (?, ?, ?, ?, ?);
	`, username, signature, arr2json(requestData.Questions), arr2json(requestData.Answers), time.Now().Format(time.RFC3339))
	if err != nil {
		http.Error(w, "Error storing signature", http.StatusInternalServerError)
		return
	}

	// Return the signature
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"signature": signature})
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Username  string
		Signature string
	}

	var responseData struct {
		Answers   []string
		Timestamp time.Time
	}

	// Decode the JSON request body into struct
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var answers string
	// Retrieve data from the database for the given username
	err = db.QueryRow("SELECT answers, timestamp FROM signatures WHERE user = ? AND signature = ?", requestData.Username, requestData.Signature).
		Scan(&answers, &responseData.Timestamp)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Signature not found", http.StatusNotFound)
		} else {
			http.Error(w, "Error retrieving signature", http.StatusInternalServerError)
		}
		return
	}
	responseData.Answers = json2arr(answers)

	// Return the signature
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseData)
}

func signString(message string, secretKey []byte) (string, error) {
	msg := []byte(message)
	h := hmac.New(sha256.New, secretKey)
	_, err := h.Write([]byte(msg))
	if err != nil {
		return "", err
	}
	signature := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func arr2json(arr []string) string {
	data, err := json.Marshal(arr)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func json2arr(s string) []string {
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		panic(err)
	}
	return arr
}
