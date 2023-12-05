package main

import (
	"encoding/json"
	"fmt"
	"last_hope/cipher"
	"last_hope/entity"
	"log"
	"net/http"
	"time"
)

var (
	MaxTimeDifference = time.Minute * 5
	ServiceName       = "Server"
	LongTermKey       = "75892C1452ABB04C1D1C5E5BF041D885"
	sessionKeys       = make(map[string]string)
)

func SendKey(w http.ResponseWriter, r *http.Request) {
	var request entity.SessionKeyExchangeRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tgs := entity.TicketGrantingService{}
	decryptedTgs, err := cipher.Decrypt(request.TicketGrantingServiceEncrypted, LongTermKey)
	if err != nil {
		http.Error(w, "Wrong TGS cipher", http.StatusUnauthorized)
		return
	}
	err = json.Unmarshal([]byte(decryptedTgs), &tgs)
	if err != nil {
		http.Error(w, "Wrong TGS cipher", http.StatusUnauthorized)
		return
	}

	var requestTime time.Time
	decryptedTime, err := cipher.Decrypt(request.RequestTimeEncrypted, tgs.ServerClientSessionKey)
	if err != nil {
		http.Error(w, "Wrong cipher", http.StatusUnauthorized)
		return
	}
	err = json.Unmarshal([]byte(decryptedTime), &requestTime)
	if err != nil {
		http.Error(w, "Wrong cipher", http.StatusUnauthorized)
		return
	}

	if time.Since(requestTime) > MaxTimeDifference {
		http.Error(w, fmt.Sprintf("Time difference is too big (> %d minutes)", MaxTimeDifference/time.Minute), http.StatusUnauthorized)
		return
	}

	if tgs.ServerName != ServiceName {
		http.Error(w, "Service name in TGS is not equal to the true service name", http.StatusUnauthorized)
		return
	}

	if time.Now().Before(tgs.StartsFrom) || time.Now().After(tgs.Expires) {
		http.Error(w, "Unactive TGT", http.StatusUnauthorized)
		return
	}

	sessionKeys[tgs.Login] = tgs.ServerClientSessionKey
	lt := entity.LoginAndTime{
		Login:       tgs.Login,
		RequestTime: requestTime,
	}

	ltJSON, err := json.Marshal(lt)
	if err != nil {
		http.Error(w, "Failed to create response", http.StatusInternalServerError)
		return
	}
	rtlE, err := cipher.Encrypt(string(ltJSON), tgs.ServerClientSessionKey)
	if err != nil {
		//TODO
	}
	response := entity.SessionKeyExchangeResponse{
		RequestTimeWithLoginEncrypted: rtlE,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func SendMessage(w http.ResponseWriter, r *http.Request) {
	var message entity.SendMessageRequest
	err := json.NewDecoder(r.Body).Decode(&message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	key, exists := sessionKeys[message.Login]
	if !exists {
		http.Error(w, "I don't know you", http.StatusUnauthorized)
		return
	}

	var requestTime time.Time
	decryptedTime, err := cipher.Decrypt(message.RequestTimeEncrypted, key)
	if err != nil {
		http.Error(w, "Wrong cipher", http.StatusUnauthorized)
		return
	}
	err = json.Unmarshal([]byte(decryptedTime), &requestTime)
	if err != nil {
		http.Error(w, "Wrong cipher", http.StatusUnauthorized)
		return
	}

	if time.Since(requestTime) > MaxTimeDifference {
		http.Error(w, fmt.Sprintf("Time difference is too big (> %d minutes)", MaxTimeDifference/time.Minute), http.StatusUnauthorized)
		return
	}

	text, err := cipher.Decrypt(message.MessageEncrypted, key)
	if err != nil {
		http.Error(w, "Ошибка расшифровки вашего сообщения", http.StatusUnauthorized)
		return
	}

	log.Printf("<%s> %s: %s", requestTime.String(), message.Login, text)

	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/key", SendKey)
	http.HandleFunc("/message", SendMessage)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
