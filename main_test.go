package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestJWT(username string) string {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secretKey)
	return tokenString
}

func cleanupTestData(t *testing.T) {
	// Clean up the test data from the database
	_, err := db.Exec("DELETE FROM signatures WHERE user = ?", "testuser")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignHandler(t *testing.T) {
	cleanupTestData(t)

	// Initialize the test server
	ts := httptest.NewServer(http.HandlerFunc(signHandler))
	defer ts.Close()

	// Prepare test data
	testData := struct {
		UserJwt   string
		Questions []string
		Answers   []string
	}{
		UserJwt: generateTestJWT("testuser"),
		Questions: []string{
			"Q1: What is your favorite color?",
			"Q2: What is your favorite food?",
		},
		Answers: []string{"Blue", "Pizza"},
	}

	jsonData, err := json.Marshal(testData)
	if err != nil {
		t.Fatal(err)
	}

	// Make a POST request to the /sign endpoint
	resp, err := http.Post(ts.URL+"/sign", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	var responseBody map[string]string
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := responseBody["signature"]; !ok {
		t.Error("Expected signature in the response, but not found")
	}

	var user string
	var signature string
	var questions string
	var answers string
	var timestamp string

	err = db.QueryRow("SELECT user, signature, questions, answers, timestamp FROM signatures WHERE user = ?", "testuser").
		Scan(&user, &signature, &questions, &answers, &timestamp)
	if err != nil {
		t.Fatal(err)
	}

	if signature != responseBody["signature"] {
		t.Error("Stored signature does not match the response signature")
	}
	if questions != `["Q1: What is your favorite color?","Q2: What is your favorite food?"]` {
		t.Error("Stored questions does not match the request questions")
	}
	if answers != `["Blue","Pizza"]` {
		t.Error("Stored answers does not match the request answers")
	}
}

func TestVerifyHandler404(t *testing.T) {
	cleanupTestData(t)

	// Create a new HTTP request with JSON body
	requestData := map[string]string{
		"Username":  "testuser",
		"Signature": "mock_signature",
	}
	requestBody, _ := json.Marshal(requestData)
	request := httptest.NewRequest("POST", "/verify", bytes.NewBuffer(requestBody))
	request.Header.Set("Content-Type", "application/json")

	responseRecorder := httptest.NewRecorder()
	verifyHandler(responseRecorder, request)

	if responseRecorder.Code != http.StatusNotFound {
		t.Fatalf("Expected status code %d, got %d", http.StatusOK, responseRecorder.Code)
	}
}

func TestVerifyHandler(t *testing.T) {
	cleanupTestData(t)

	// Prepare test data
	testData := struct {
		Username  string
		Signature string
		Questions []string
		Answers   []string
		Timestamp time.Time
	}{
		Username: "testuser",
		Questions: []string{
			"Q1: What is your favorite color?",
			"Q2: What is your favorite food?",
		},
		Answers:   []string{"Blue", "Pizza"},
		Signature: "mock_signature",
		Timestamp: time.Now(),
	}

	// Store the signature in the database
	_, err := db.Exec(`
		INSERT INTO signatures (user, signature, questions, answers, timestamp)
		VALUES (?, ?, ?, ?, ?);
	`, testData.Username, testData.Signature, arr2json(testData.Questions), arr2json(testData.Answers), testData.Timestamp.Format(time.RFC3339))
	if err != nil {
		t.Fatal("Error storing signature")
	}

	// Create a new HTTP request with JSON body
	requestData := map[string]string{
		"Username":  testData.Username,
		"Signature": testData.Signature,
	}
	requestBody, _ := json.Marshal(requestData)
	request := httptest.NewRequest("POST", "/verify", bytes.NewBuffer(requestBody))
	request.Header.Set("Content-Type", "application/json")

	responseRecorder := httptest.NewRecorder()
	verifyHandler(responseRecorder, request)

	// Check the HTTP response status code
	if responseRecorder.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d", http.StatusOK, responseRecorder.Code)
	}

	// Decode the response body into a struct
	var responseData struct {
		Answers   []string
		Timestamp time.Time
	}
	err = json.NewDecoder(responseRecorder.Body).Decode(&responseData)
	if err != nil {
		t.Errorf("Error decoding JSON response: %v", err)
	}

	// Check the expected values in the response struct
	if !compareStringSlices(responseData.Answers, testData.Answers) {
		t.Errorf("Expected answers %v, got %v", testData.Answers, responseData.Answers)
	}

	if responseData.Timestamp.Format(time.RFC3339) != testData.Timestamp.Format(time.RFC3339) {
		t.Errorf("Expected timestamp %v, got %v", testData.Timestamp, responseData.Timestamp)
	}
}

func compareStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
