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

	const ip = "127.0.0.1"
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
		log.Fatal("fail encrypt request")
		return
	}
	arq := entity.AuthenticationRequest{
		Login:                login,
		RequestTimeEncrypted: aurtE,
	}
	fmt.Println("Sending AuthenticationRequest... ")
	arsp := entity.AuthenticationResponse{}
	err = postRequest(client, fmt.Sprintf("http://%s:%s/TGT", ip, kdcPort), arq, &arsp)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Success! Response:")
	//fmt.Println(arsp)

	skt := entity.SessionKeyAndTime{}
	err = DecryptAndDeserialize(arsp.SessionKeyAndRequestTimeEncrypted, longTermKey, &skt)
	//fmt.Printf("SKT:::::::::::::%+v", skt)
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
	fmt.Println(len(kdcSessionKey))
	//sessionKeyHex := hex.EncodeToString([]byte(skt.SessionKey))
	//fmt.Println("Session Key (hex):", sessionKeyHex)

	grantingServiceRequestTime := time.Now().UTC()
	//fmt.Println(grantingServiceRequestTime)
	gsrE, err := cipher.Encrypt(jsonSerialize(grantingServiceRequestTime), kdcSessionKey)
	//fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	//fmt.Println(cipher.Decrypt(gsrE, kdcSessionKey))
	if err != nil {
		log.Fatal("encrypt fault")
		return
	}
	gsr := entity.GrantingServiceRequest{
		Login:                         login,
		RequestTimeEncrypted:          gsrE,
		ServiceName:                   "Server",
		TicketGrantingTicketEncrypted: tgt,
	}
	fmt.Println("Sending GrantingServiceRequest...")
	gsrsp := entity.GrantingServiceResponse{}

	//fmt.Printf("\n %+v", gsr)
	err = postRequest(client, fmt.Sprintf("http://%s:%s/TGS", ip, kdcPort), gsr, &gsrsp)
	//fmt.Printf("\n %+v", gsrsp)
	if err != nil {
		//fmt.Printf("%+v", gsrsp)
		log.Fatal(err)
	}

	fmt.Println("Success! Response:")

	tgscs := entity.TicketForClientAndForServer{}
	err = DecryptAndDeserialize(gsrsp.TicketForClientAndForServerEncrypted, kdcSessionKey, &tgscs)
	fmt.Printf("err: %w, login: %s, name: %s", err, tgscs.Ticket.Login, tgscs.Ticket.ServerName)
	if err != nil || tgscs.Ticket.Login != login || tgscs.Ticket.ServerName != "Server" {
		log.Fatal("Wrong TGS ticket")
		return
	}

	// SessionKeyExchangeRequest
	fmt.Println("Creating SessionKeyExchangeRequest...")
	//serverSessionKey := tgscs.Ticket.ServerClientSessionKey
	sessionKeyExchangeRequestTime := time.Now().UTC()
	rtE, err := cipher.Encrypt(jsonSerialize(sessionKeyExchangeRequestTime), kdcSessionKey)
	if err != nil {
		log.Fatal("encrypt fault")
		return
	}
	skerq := entity.SessionKeyExchangeRequest{
		RequestTimeEncrypted:           rtE,
		TicketGrantingServiceEncrypted: tgscs.TicketEncrypted,
	}
	fmt.Println("Sending SessionKeyExchangeRequest...")
	skersp := entity.SessionKeyExchangeResponse{}
	err = postRequest(client, fmt.Sprintf("http://%s:%s/key", ip, serverPort), skerq, &skersp)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Success!Response:")
	//fmt.Println(skersp)

	loginAndTime := entity.LoginAndTime{}
	err = DecryptAndDeserialize(skersp.RequestTimeWithLoginEncrypted, kdcSessionKey, &loginAndTime)
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
		log.Fatalf("do request error %w", err)
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("body %+v", resp)
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

	err = json.Unmarshal([]byte(decryptedText), &target)
	if err != nil {
		return err
	}

	return nil
}
