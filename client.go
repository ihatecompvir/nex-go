package nex

import (
	"crypto/rc4"
	"net"
)

// Client represents a connected or non-connected PRUDP client
type Client struct {
	address                   *net.UDPAddr
	server                    *Server
	cipher                    *rc4.Cipher
	decipher                  *rc4.Cipher
	signatureKey              []byte
	signatureBase             int
	secureKey                 []byte
	serverConnectionSignature []byte
	clientConnectionSignature []byte
	sessionID                 int
	sessionKey                []byte
	sequenceIDIn              *Counter
	sequenceIDOut             *Counter
	Username                  string
	WiiFC                     string
	connectionID              uint32
	externalStationURL        string

	// this enables per-client incoming fragmented packet support
	lastFragmentSequenceID uint16
	fragmentedPayloadData  []byte
}

// Reset resets the Client to default values
func (client *Client) Reset() {
	client.sequenceIDIn = NewCounter(0)
	client.sequenceIDOut = NewCounter(0)
	client.lastFragmentSequenceID = 0
	client.fragmentedPayloadData = make([]byte, 0)

	client.UpdateAccessKey(client.Server().AccessKey())
	client.UpdateRC4Key([]byte("CD&ML"))

	if client.Server().PrudpVersion() == 0 {
		client.SetServerConnectionSignature(make([]byte, 4))
		client.SetClientConnectionSignature(make([]byte, 4))
	} else {
		client.SetServerConnectionSignature([]byte{})
		client.SetClientConnectionSignature([]byte{})
	}
}

// Address returns the clients UDP address
func (client *Client) Address() *net.UDPAddr {
	return client.address
}

// Server returns the server the client is currently connected to
func (client *Client) Server() *Server {
	return client.server
}

// UpdateRC4Key sets the client RC4 stream key
func (client *Client) UpdateRC4Key(RC4Key []byte) {
	cipher, _ := rc4.NewCipher(RC4Key)
	client.cipher = cipher

	decipher, _ := rc4.NewCipher(RC4Key)
	client.decipher = decipher
}

// Cipher returns the RC4 cipher stream for out-bound packets
func (client *Client) Cipher() *rc4.Cipher {
	// This solves a bug where the RC4 cipher gets messed up somehow after encrypting the first packet
	client.cipher, _ = rc4.NewCipher([]byte("CD&ML"))
	return client.cipher
}

// Decipher returns the RC4 cipher stream for in-bound packets
func (client *Client) Decipher() *rc4.Cipher {
	// This solves a bug where the RC4 cipher gets messed up somehow after decrypting the first packet
	client.decipher, _ = rc4.NewCipher([]byte("CD&ML"))
	return client.decipher
}

// UpdateAccessKey sets the client signature base and signature key
func (client *Client) UpdateAccessKey(accessKey string) {
	client.signatureBase = sum([]byte(accessKey))
	client.signatureKey = MD5Hash([]byte(accessKey))
}

// SignatureBase returns the v0 checksum signature base
func (client *Client) SignatureBase() int {
	return client.signatureBase
}

// SignatureKey returns signature key
func (client *Client) SignatureKey() []byte {
	return client.signatureKey
}

// SetServerConnectionSignature sets the clients server-side connection signature
func (client *Client) SetServerConnectionSignature(serverConnectionSignature []byte) {
	client.serverConnectionSignature = serverConnectionSignature
}

// ServerConnectionSignature returns the clients server-side connection signature
func (client *Client) ServerConnectionSignature() []byte {
	return client.serverConnectionSignature
}

// SetClientConnectionSignature sets the clients client-side connection signature
func (client *Client) SetClientConnectionSignature(clientConnectionSignature []byte) {
	client.clientConnectionSignature = clientConnectionSignature
}

// ClientConnectionSignature returns the clients client-side connection signature
func (client *Client) ClientConnectionSignature() []byte {
	return client.clientConnectionSignature
}

// SequenceIDCounterOut returns the clients packet SequenceID counter for out-going packets
func (client *Client) SequenceIDCounterOut() *Counter {
	return client.sequenceIDOut
}

// SequenceIDCounterIn returns the clients packet SequenceID counter for incoming packets
func (client *Client) SequenceIDCounterIn() *Counter {
	return client.sequenceIDIn
}

// SetSessionKey sets the clients session key
func (client *Client) SetSessionKey(sessionKey []byte) {
	client.sessionKey = sessionKey
}

// SessionKey returns the clients session key
func (client *Client) SessionKey() []byte {
	return client.sessionKey
}

// SetExternalStationURL sets the clients external station URL
func (client *Client) SetExternalStationURL(externalStationURL string) {
	client.externalStationURL = externalStationURL
}

// SetExternalStationURL returns the clients external station URL
func (client *Client) ExternalStationURL() string {
	return client.externalStationURL
}

func (client *Client) LastFragmentSequenceID() uint16 {
	return client.lastFragmentSequenceID
}

func (client *Client) SetLastFragmentSequenceID(sequenceID uint16) {
	client.lastFragmentSequenceID = sequenceID
}

func (client *Client) FragmentedPayloadData() []byte {
	return client.fragmentedPayloadData
}

func (client *Client) SetFragmentedPayloadData(data []byte) {
	client.fragmentedPayloadData = data
}

// SetConnectionID sets the clients Connection ID
func (client *Client) SetConnectionID(connectionID uint32) {
	client.connectionID = connectionID
}

// ConnectionID returns the clients Connection ID
func (client *Client) ConnectionID() uint32 {
	return client.connectionID
}

// NewClient returns a new PRUDP client
func NewClient(address *net.UDPAddr, server *Server) *Client {
	client := &Client{
		address: address,
		server:  server,
	}

	client.Reset()

	return client
}
