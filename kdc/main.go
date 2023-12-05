package main

import (
	"encoding/hex"
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
	"user":   "5cc32e366c87c4cb49e4309b75f57d64",
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
	//decryptedTime := "747171b34cc8c9538a8123e6e2b9757506e58d682c6f1935a58900caa6aace7d855581b3c6c43b7211cc5e21e5c669db"
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
	//fmt.Println("Key size: ")
	//генерация случайного ключа

	kdcClientSessionKey, err := cipher.Generate128BitsOfRandomEntropy()
	//fmt.Println(string(kdcClientSessionKey))
	kdcClientSessionKey2 := hex.EncodeToString(kdcClientSessionKey)

	//fmt.Println(kdcClientSessionKey)
	if err != nil {
		//TODO:
		return
	}
	tgt := entity.TicketGrantingTicket{
		Login:               request.Login,
		KdcClientSessionKey: kdcClientSessionKey2,
		StartsFrom:          time.Now().UTC(),
		Expires:             time.Now().UTC().Add(MaxTicketLife),
	}

	skt := entity.SessionKeyAndTime{
		SessionKey:  kdcClientSessionKey2,
		RequestTime: requestTime,
	}

	tgtJSON, err := json.Marshal(tgt)
	if err != nil {
		log.Fatal("json marshal")
		return
	}
	sktJSON, err := json.Marshal(skt)
	if err != nil {
		log.Fatal("json marhal fault")
		return
	}
	tgtE, err := cipher.Encrypt(string(tgtJSON), MasterKey)
	if err != nil {
		log.Fatal("marshal tgt")
	}
	skenc, err := cipher.Encrypt(string(sktJSON), key)
	fmt.Println(skenc)
	if err != nil {
		log.Fatal("marshal skenc")
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
	//fmt.Println(decryptedTgt)
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
	serverClientSessionKey2, err := cipher.Generate128BitsOfRandomEntropy()
	serverClientSessionKey := hex.EncodeToString(serverClientSessionKey2)
	if err != nil {
		return
	}
	tgs := entity.TicketGrantingService{
		Login:                  request.Login,
		ServerName:             request.ServiceName,
		ServerClientSessionKey: serverClientSessionKey,
		StartsFrom:             time.Now().UTC(),
		Expires:                time.Now().UTC().Add(MaxTicketLife),
	}

	serverKey, ok := longTermKeys[request.ServiceName]
	if !ok {
		http.Error(w, "No such Service", http.StatusBadRequest)
		return
	}
	tgsJSON, err := json.Marshal(tgt)
	if err != nil {
		// Обработка ошибки сериализации в JSON
	}
	tgsE, err := cipher.Encrypt(string(tgsJSON), serverKey)
	if err != nil {
		log.Fatalf("encrypt error")
		return
	}
	tcs := entity.TicketForClientAndForServer{
		Ticket:          tgs,
		TicketEncrypted: tgsE,
	}
	tcsJSON, err := json.Marshal(tcs)
	if err != nil {
		log.Fatalf("marshal error")
		return
	}
	tcsE, err := cipher.Encrypt(string(tcsJSON), key)
	if err != nil {
		log.Fatalf("encrypt error")
		return
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
