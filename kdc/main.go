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

const (
	MasterKey         = "71337336763979244226452948404D63"
	MaxTimeDifference = 5 // In minutes
	MaxTicketLife     = 10 * time.Hour
)

var longTermKeys = map[string]string{
	"user":   "AD42C83AC4D3B86DE14F207C46A0DF0E",
	"Server": "75892C1452ABB04C1D1C5E5BF041D885",
}

func getTGT(w http.ResponseWriter, r *http.Request) {
	var request entity.AuthenticationRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	fmt.Printf("%s connected to get TGT\n", request.Login)

	key, ok := longTermKeys[request.Login]
	if !ok {
		http.Error(w, "There is no such user", http.StatusUnauthorized)
		return
	}

	var requestTime time.Time

	decryptedTime, err := cipher.Decrypt(request.RequestTimeEncrypted, key)
	if err != nil {
		http.Error(w, "Wrong cipher", http.StatusUnauthorized)
		return
	}
	fmt.Println(decryptedTime)
	err = json.Unmarshal([]byte(decryptedTime), &requestTime)
	if err != nil {
		http.Error(w, "Wrong cipher", http.StatusUnauthorized)
		return
	}

	if time.Since(requestTime).Minutes() > MaxTimeDifference {
		http.Error(w, fmt.Sprintf("Time difference is too big (> %d minutes)", MaxTimeDifference), http.StatusUnauthorized)
		return
	}

	kdcClientSessionKey, err := cipher.Generate128BitsOfRandomEntropy()
	if err != nil {
		//TODO:
		return
	}
	tgt := entity.TicketGrantingTicket{
		Login:               request.Login,
		KdcClientSessionKey: string(kdcClientSessionKey),
		StartsFrom:          time.Now().UTC(),
		Expires:             time.Now().UTC().Add(MaxTicketLife),
	}

	skt := entity.SessionKeyAndTime{
		SessionKey:  tgt.KdcClientSessionKey,
		RequestTime: requestTime,
	}

	tgtJSON, err := json.Marshal(tgt)
	if err != nil {
		log.Fatal("json marshal")
		return
	}
	sktJSON, err := json.Marshal(skt)
	if err != nil {
		//TODO:
	}
	tgtE, err := cipher.Encrypt(string(tgtJSON), MasterKey)
	if err != nil {
		//TODO:
	}
	skenc, err := cipher.Encrypt(string(sktJSON), key)
	if err != nil {
		//TODO:
	}
	ar := entity.AuthenticationResponse{
		TicketGrantingTicketEncrypted:     tgtE,
		SessionKeyAndRequestTimeEncrypted: skenc,
	}

	fmt.Printf("%s got TGT\n", request.Login)
	jsonResponse(w, ar)
}

func getTGS(w http.ResponseWriter, r *http.Request) {
	var request entity.GrantingServiceRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	fmt.Printf("%s connected to get TGS\n", request.Login)

	decryptedTgt, err := cipher.Decrypt(request.TicketGrantingTicketEncrypted, MasterKey)
	fmt.Println(decryptedTgt)
	if err != nil {
		http.Error(w, "Wrong TGT", http.StatusUnauthorized)
		return
	}

	var tgt entity.TicketGrantingTicket
	err = json.Unmarshal([]byte(decryptedTgt), &tgt)
	if err != nil {
		http.Error(w, "Wrong TGT", http.StatusUnauthorized)
		return
	}

	key := tgt.KdcClientSessionKey

	var requestTime time.Time
	decryptedTime, err := cipher.Decrypt(request.RequestTimeEncrypted, key)
	if err != nil {
		http.Error(w, "Wrong cipher", http.StatusUnauthorized)
		return
	}

	err = json.Unmarshal([]byte(decryptedTime), &requestTime)
	if err != nil {
		http.Error(w, "Wrong cipher", http.StatusUnauthorized)
		return
	}

	if time.Since(requestTime).Minutes() > MaxTimeDifference {
		http.Error(w, fmt.Sprintf("Time difference is too big (> %d minutes)", MaxTimeDifference), http.StatusUnauthorized)
		return
	}

	if tgt.Login != request.Login {
		http.Error(w, "Login in TGT is not equal to the request login", http.StatusUnauthorized)
		return
	}

	if time.Now().UTC().Before(tgt.StartsFrom) || time.Now().UTC().After(tgt.Expires) {
		http.Error(w, "Unactive TGT", http.StatusUnauthorized)
		return
	}
	serverClientSessionKey, err := cipher.Generate128BitsOfRandomEntropy()
	if err != nil {
		return
	}
	tgs := entity.TicketGrantingService{
		Login:                  request.Login,
		ServerName:             request.ServiceName,
		ServerClientSessionKey: string(serverClientSessionKey),
		StartsFrom:             time.Now().UTC(),
		Expires:                time.Now().UTC().Add(MaxTicketLife),
	}

	_, ok := longTermKeys[request.ServiceName]
	if !ok {
		http.Error(w, "No such Service", http.StatusBadRequest)
		return
	}
	tgsJSON, err := json.Marshal(tgt)
	if err != nil {
		// Обработка ошибки сериализации в JSON
	}
	tgsE, err := cipher.Encrypt(string(tgsJSON), MasterKey)
	if err != nil {
		//TODO:
	}
	tcs := entity.TicketForClientAndForServer{
		Ticket:          tgs,
		TicketEncrypted: tgsE,
	}
	tcsJSON, err := json.Marshal(tcs)
	if err != nil {
		//TODO
	}
	tcsE, err := cipher.Encrypt(string(tcsJSON), MasterKey)
	if err != nil {
		//TODO:
	}
	gsr := entity.GrantingServiceResponse{
		TicketForClientAndForServerEncrypted: tcsE,
	}

	fmt.Printf("%s got TGS\n", request.Login)
	jsonResponse(w, gsr)
}

func main() {
	http.HandleFunc("/TGT", getTGT)
	http.HandleFunc("/TGS", getTGS)

	log.Fatal(http.ListenAndServe("localhost:7089", nil))
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
