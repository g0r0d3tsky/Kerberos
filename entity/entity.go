package entity

import "time"

//for server

type SessionKeyExchangeRequest struct {
	TicketGrantingServiceEncrypted string `json:"ticketGrantingServiceEncrypted"`
	RequestTimeEncrypted           string `json:"requestTimeEncrypted"`
}

type TicketGrantingService struct {
	ServerName             string    `json:"serverName"`
	StartsFrom             time.Time `json:"startsFrom"`
	Expires                time.Time `json:"expires"`
	ServerClientSessionKey string    `json:"kdcClientSessionKey"`
	Login                  string    `json:"login"`
}

type LoginAndTime struct {
	Login       string    `json:"login"`
	RequestTime time.Time `json:"requestTime"`
}

type SessionKeyExchangeResponse struct {
	RequestTimeWithLoginEncrypted string `json:"requestTimeWithLoginEncrypted"`
}

type SendMessageRequest struct {
	MessageEncrypted     string `json:"messageEncrypted"`
	Login                string `json:"login"`
	RequestTimeEncrypted string `json:"requestTimeEncrypted"`
}

// for client
type SessionKeyAndTime struct {
	SessionKey  string    `json:"sessionKey"`
	RequestTime time.Time `json:"requestTime"`
}

type TicketForClientAndForServer struct {
	Ticket          TicketGrantingService `json:"ticket"`
	TicketEncrypted string                `json:"ticketEncrypted"`
}

type AuthenticationRequest struct {
	Login                string `json:"login"`
	RequestTimeEncrypted string `json:"requestTimeEncrypted"`
}

type AuthenticationResponse struct {
	TicketGrantingTicketEncrypted     string `json:"ticketGrantingTicketEncrypted"`
	SessionKeyAndRequestTimeEncrypted string `json:"sessionKeyAndRequestTimeEncrypted"`
}

type GrantingServiceRequest struct {
	Login                         string `json:"login"`
	RequestTimeEncrypted          string `json:"requestTimeEncrypted"`
	ServiceName                   string `json:"serviceName"`
	TicketGrantingTicketEncrypted string `json:"ticketGrantingTicketEncrypted"`
}

type GrantingServiceResponse struct {
	TicketForClientAndForServerEncrypted string `json:"ticketForClientAndForServerEncrypted"`
}

//for kdc

type TicketGrantingTicket struct {
	Login               string    `json:"login"`
	KdcClientSessionKey string    `json:"kdcClientSessionKey"`
	StartsFrom          time.Time `json:"startsFrom"`
	Expires             time.Time `json:"expires"`
}
