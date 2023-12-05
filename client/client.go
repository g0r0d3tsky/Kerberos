package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"last_hope/cipher"
	"last_hope/entity"
	"log"
	"net/http"
	"time"
)

func main() {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	const ip = "localhost"
	const kdcPort = "7089"
	const serverPort = "7055"

	var login, password string
	fmt.Print("Enter Login: ")
	fmt.Scanln(&login)
	fmt.Print("Enter Password: ")
	fmt.Scanln(&password)

	longTermKey := cipher.CreateMD5(password + login)
	fmt.Printf("[DEBUG]: Generated long-term key %s\n", longTermKey)

	// AuthenticationRequest
	fmt.Println("Creating AuthenticationRequest...")

	authenticationRequestTime := time.Now().UTC()
	aurtE, err := cipher.Encrypt(jsonSerialize(authenticationRequestTime), longTermKey)
	if err != nil {
		//TODO
	}
	arq := entity.AuthenticationRequest{
		Login:                login,
		RequestTimeEncrypted: aurtE,
	}
	fmt.Println("Sending AuthenticationRequest...")
	arsp := entity.AuthenticationResponse{}
	err = postRequest(client, fmt.Sprintf("https://%s:%s/TGT", ip, kdcPort), arq, &arsp)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Success! Response:")
	fmt.Println(arsp)

	skt := entity.SessionKeyAndTime{}
	err = DecryptAndDeserialize(arsp.SessionKeyAndRequestTimeEncrypted, longTermKey, &skt)
	if err != nil {
		log.Fatal("KDC has wrong long-term key")
	}
	if skt.RequestTime != authenticationRequestTime {
		log.Fatal("KDC has wrong long-term key")
	}

	// GrantingServiceRequest
	fmt.Println("Creating GrantingServiceRequest...")
	tgt := arsp.TicketGrantingTicketEncrypted
	kdcSessionKey := skt.SessionKey
	grantingServiceRequestTime := time.Now().UTC()
	gsrE, err := cipher.Encrypt(jsonSerialize(grantingServiceRequestTime), kdcSessionKey)
	if err != nil {
		//TODO
	}
	gsr := entity.GrantingServiceRequest{
		Login:                         login,
		RequestTimeEncrypted:          gsrE,
		ServiceName:                   "Server",
		TicketGrantingTicketEncrypted: tgt,
	}
	fmt.Println("Sending GrantingServiceRequest...")
	gsrsp := entity.GrantingServiceResponse{}
	err = postRequest(client, fmt.Sprintf("https://%s:%s/TGS", ip, kdcPort), gsr, &gsrsp)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Success! Response:")
	fmt.Println(gsrsp)

	tgscs := entity.TicketForClientAndForServer{}
	err = DecryptAndDeserialize(gsrsp.TicketForClientAndForServerEncrypted, kdcSessionKey, &tgscs)
	if err != nil || tgscs.Ticket.Login != login || tgscs.Ticket.ServerName != "Server" {
		log.Fatal("Wrong TGS ticket")
	}

	// SessionKeyExchangeRequest
	fmt.Println("Creating SessionKeyExchangeRequest...")
	serverSessionKey := tgscs.Ticket.ServerClientSessionKey
	sessionKeyExchangeRequestTime := time.Now().UTC()
	rtE, err := cipher.Encrypt(jsonSerialize(sessionKeyExchangeRequestTime), serverSessionKey)
	if err != nil {
		//TODO:
	}
	skerq := entity.SessionKeyExchangeRequest{
		RequestTimeEncrypted:           rtE,
		TicketGrantingServiceEncrypted: tgscs.TicketEncrypted,
	}
	fmt.Println("Sending SessionKeyExchangeRequest...")
	skersp := entity.SessionKeyExchangeResponse{}
	err = postRequest(client, fmt.Sprintf("https://%s:%s/key", ip, serverPort), skerq, &skersp)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Success!Response:")
	fmt.Println(skersp)

	loginAndTime := entity.LoginAndTime{}
	err = DecryptAndDeserialize(skersp.RequestTimeWithLoginEncrypted, serverSessionKey, &loginAndTime)
	if err != nil || loginAndTime.Login != login || loginAndTime.RequestTime != sessionKeyExchangeRequestTime {
		log.Fatal("Server sent wrong request")
	}
}

func postRequest(client *http.Client, url string, requestData interface{}, responseData interface{}) error {
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(responseData)
	if err != nil {
		return err
	}

	return nil
}

func jsonSerialize(data interface{}) string {
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

func DecryptAndDeserialize(cipherText string, passPhrase string, target interface{}) error {
	decryptedText, err := cipher.Decrypt(cipherText, passPhrase)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(decryptedText), target)
	if err != nil {
		return err
	}

	return nil
}
