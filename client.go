package nex

import (
	"crypto/rc4"
	"net"
	"sync"
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
	sequenceIDIn              *Counter // how many packets have gone in
	sequenceIDOut             *Counter // how many packets have gone out
	Username                  string   // the platform username of the client, "Master User (FRIEND CODE)" on Wii
	WiiFC                     string   // only used for Wii, Friend Code
	connectionID              uint32   // RVCID, Rendez-vous Connection ID
	playerID                  uint32   // PID, PlayerID
	externalStationURL        string   // used for NAT probing
	platform                  int      // the platform the client is connecting from
	machineID                 int      // the machine ID of the client

	// this enables per-client incoming fragmented packet support
	fragmentMutex      sync.Mutex
	fragmentedPayloads map[uint8][]byte // fragmentID -> payload data
}

// Reset resets the Client to default values
func (client *Client) Reset() {
	client.sequenceIDIn = NewCounter(0)
	client.sequenceIDOut = NewCounter(0)
	client.fragmentedPayloads = make(map[uint8][]byte)

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

// LockFragmentState locks the fragment mutex for thread-safe fragment reassembly
func (client *Client) LockFragmentState() {
	client.fragmentMutex.Lock()
}

// UnlockFragmentState unlocks the fragment mutex
func (client *Client) UnlockFragmentState() {
	client.fragmentMutex.Unlock()
}

// StoreFragment stores a fragment payload by its fragment ID (must hold lock)
func (client *Client) StoreFragment(fragmentID uint8, data []byte) {
	client.fragmentedPayloads[fragmentID] = data
}

// HasFragments returns true if there are buffered fragments (must hold lock)
func (client *Client) HasFragments() bool {
	return len(client.fragmentedPayloads) > 0
}

// AssembleFragments assembles all buffered fragments in order and clears the buffer (must hold lock)
func (client *Client) AssembleFragments(finalPayload []byte) []byte {
	// Find the highest fragment ID to know how many fragments we have
	var maxFragmentID uint8 = 0
	for id := range client.fragmentedPayloads {
		if id > maxFragmentID {
			maxFragmentID = id
		}
	}

	// Assemble fragments in order: 1, 2, 3, ..., maxFragmentID, then the final payload (fragmentID 0)
	var assembled []byte
	for i := uint8(1); i <= maxFragmentID; i++ {
		if fragment, ok := client.fragmentedPayloads[i]; ok {
			assembled = append(assembled, fragment...)
		}
	}
	assembled = append(assembled, finalPayload...)

	// Clear the fragment buffer
	client.fragmentedPayloads = make(map[uint8][]byte)

	return assembled
}

// ClearFragmentState resets fragment reassembly state (must hold lock)
func (client *Client) ClearFragmentState() {
	client.fragmentedPayloads = make(map[uint8][]byte)
}

// SetConnectionID sets the clients Connection ID
func (client *Client) SetConnectionID(connectionID uint32) {
	client.connectionID = connectionID
}

// ConnectionID returns the clients Connection ID
func (client *Client) ConnectionID() uint32 {
	return client.connectionID
}

// SetPlayerID sets the clients Player ID
func (client *Client) SetPlayerID(playerID uint32) {
	client.playerID = playerID
}

// PlayerID returns the clients Player ID
func (client *Client) PlayerID() uint32 {
	return client.playerID
}

// SetPlatform sets the clients platform
func (client *Client) SetPlatform(platform int) {
	client.platform = platform
}

// Platform returns the clients platform
func (client *Client) Platform() int {
	return client.platform
}

// SetMachineID sets the clients machine ID
func (client *Client) SetMachineID(machineID int) {
	client.machineID = machineID
}

// MachineID returns the clients machine ID
func (client *Client) MachineID() int {
	return client.machineID
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
