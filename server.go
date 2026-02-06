package nex

import (
	"log"
	"math"
	"net"
	"runtime"
	"sync"
	"time"
)

// Server represents a PRUDP server
type Server struct {
	socket                *net.UDPConn
	compressPacket        func([]byte) []byte
	decompressPacket      func([]byte) []byte
	clients               map[string]*Client
	clientMutex           sync.RWMutex
	genericEventHandles   map[string][]func(PacketInterface)
	prudpV0EventHandles   map[string][]func(*PacketV0)
	accessKey             string
	prudpVersion          int
	nexVersion            int
	fragmentSize          int16
	resendTimeout         float32
	usePacketCompression  bool
	pingTimeout           int
	signatureVersion      int
	flagsVersion          int
	checksumVersion       int
	kerberosKeySize       int
	kerberosKeyDerivation int
	serverVersion         int
	connectionIDCounter   *Counter
}

// Listen starts a NEX server on a given address
func (server *Server) Listen(address string) {

	protocol := "udp"

	udpAddress, err := net.ResolveUDPAddr(protocol, address)

	if err != nil {
		panic(err)
	}

	socket, err := net.ListenUDP(protocol, udpAddress)

	if err != nil {
		panic(err)
	}

	server.SetSocket(socket)

	quit := make(chan struct{})

	for i := 0; i < runtime.NumCPU(); i++ {
		go server.listenDatagram(quit)
	}

	log.Printf("Rendez-vous server now listening on address %s\n", udpAddress)

	server.Emit("Listening", nil)

	<-quit
}

func (server *Server) listenDatagram(quit chan struct{}) {
	err := error(nil)

	for err == nil {
		err = server.handleSocketMessage()
	}

	quit <- struct{}{}

	panic(err)
}

func (server *Server) handleSocketMessage() error {
	var buffer [64000]byte

	socket := server.Socket()

	length, addr, err := socket.ReadFromUDP(buffer[0:])

	if err != nil {
		return err
	}

	discriminator := addr.String()

	server.clientMutex.Lock()
	if _, ok := server.clients[discriminator]; !ok {
		server.clients[discriminator] = NewClient(addr, server)
	}
	client := server.clients[discriminator]
	server.clientMutex.Unlock()

	data := buffer[0:length]

	// Serialize packet decode + event dispatch per-client to prevent racing
	// please fix it :despair:
	client.LockProcessing()
	defer client.UnlockProcessing()

	var packet PacketInterface

	packet, err = NewPacketV0(client, data)

	if err != nil {
		log.Println(err)
		return nil
	}

	if packet.HasFlag(FlagAck) {
		return nil
	}

	if packet.HasFlag(FlagNeedsAck) {
		if packet.Type() != ConnectPacket || (packet.Type() == ConnectPacket && len(packet.Payload()) <= 0) {
			go server.AcknowledgePacket(packet, nil)
		}
	}

	switch packet.Type() {
	case SynPacket:
		client.Reset()
		server.Emit("Syn", packet)
	case ConnectPacket:
		packet.Sender().SetClientConnectionSignature(packet.ConnectionSignature())

		server.Emit("Connect", packet)
	case DataPacket:
		// only emit Data event for complete packets, not partial fragments
		if !packet.IsPartialFragment() {
			server.Emit("Data", packet)
		}
	case DisconnectPacket:
		server.Kick(client)
		server.Emit("Disconnect", packet)
	case PingPacket:
		server.SendPing(client)
		server.Emit("Ping", packet)
	}

	server.Emit("Packet", packet)

	return nil
}

// On sets the data event handler
func (server *Server) On(event string, handler interface{}) {
	// Check if the handler type matches one of the allowed types, and store the handler in it's allowed property
	// Need to cast the handler to the correct function type before storing
	switch handler.(type) {
	case func(PacketInterface):
		server.genericEventHandles[event] = append(server.genericEventHandles[event], handler.(func(PacketInterface)))
	case func(*PacketV0):
		server.prudpV0EventHandles[event] = append(server.prudpV0EventHandles[event], handler.(func(*PacketV0)))
	}
}

// Emit runs the given event handle
func (server *Server) Emit(event string, packet interface{}) {

	eventName := server.genericEventHandles[event]
	for i := 0; i < len(eventName); i++ {
		handler := eventName[i]
		packet := packet.(PacketInterface)
		go handler(packet)
	}

	// Check if the packet type matches one of the allowed types and run the given handler

	switch packet.(type) {
	case *PacketV0:
		eventName := server.prudpV0EventHandles[event]
		for i := 0; i < len(eventName); i++ {
			handler := eventName[i]
			go handler(packet.(*PacketV0))
		}
	}
}

// ClientConnected checks if a given client is stored on the server
func (server *Server) ClientConnected(client *Client) bool {
	discriminator := client.Address().String()

	server.clientMutex.RLock()
	_, connected := server.clients[discriminator]
	server.clientMutex.RUnlock()

	return connected
}

// Kick removes a client from the server
func (server *Server) Kick(client *Client) {
	discriminator := client.Address().String()

	server.clientMutex.Lock()
	if _, ok := server.clients[discriminator]; ok {
		delete(server.clients, discriminator)
		log.Println("Kicked user", discriminator)
	}
	server.clientMutex.Unlock()
}

// SendPing sends a ping packet to the given client
func (server *Server) SendPing(client *Client) {
	var pingPacket PacketInterface

	pingPacket, _ = NewPacketV0(client, nil)

	pingPacket.SetSource(0x31)
	pingPacket.SetDestination(0x3F)
	pingPacket.SetType(PingPacket)
	pingPacket.AddFlag(FlagNeedsAck)
	pingPacket.AddFlag(FlagReliable)

	server.Send(pingPacket)
}

// AcknowledgePacket acknowledges that the given packet was recieved
func (server *Server) AcknowledgePacket(packet PacketInterface, payload []byte) {
	sender := packet.Sender()

	var ackPacket PacketInterface

	ackPacket, _ = NewPacketV0(sender, nil)

	ackPacket.SetSource(packet.Destination())
	ackPacket.SetDestination(packet.Source())
	ackPacket.SetType(packet.Type())
	ackPacket.SetSequenceID(packet.SequenceID())
	ackPacket.SetFragmentID(packet.FragmentID())
	ackPacket.AddFlag(FlagAck)

	if payload != nil {
		ackPacket.SetPayload(payload)
	}

	data := ackPacket.Bytes()

	server.SendRaw(sender.Address(), data)
}

// Socket returns the underlying server UDP socket
func (server *Server) Socket() *net.UDPConn {
	return server.socket
}

// SetSocket sets the underlying UDP socket
func (server *Server) SetSocket(socket *net.UDPConn) {
	server.socket = socket
}

// PrudpVersion returns the server PRUDP version
func (server *Server) PrudpVersion() int {
	return server.prudpVersion
}

// SetPrudpVersion sets the server PRUDP version
func (server *Server) SetPrudpVersion(prudpVersion int) {
	server.prudpVersion = prudpVersion
}

// NexVersion returns the server NEX version
func (server *Server) NexVersion() int {
	return server.nexVersion
}

// SetNexVersion sets the server NEX version
func (server *Server) SetNexVersion(nexVersion int) {
	server.nexVersion = nexVersion
}

// ChecksumVersion returns the server packet checksum version
func (server *Server) ChecksumVersion() int {
	return server.checksumVersion
}

// SetChecksumVersion sets the server packet checksum version
func (server *Server) SetChecksumVersion(checksumVersion int) {
	server.checksumVersion = checksumVersion
}

// FlagsVersion returns the server packet flags version
func (server *Server) FlagsVersion() int {
	return server.flagsVersion
}

// SetFlagsVersion sets the server packet flags version
func (server *Server) SetFlagsVersion(flagsVersion int) {
	server.flagsVersion = flagsVersion
}

// AccessKey returns the server access key
func (server *Server) AccessKey() string {
	return server.accessKey
}

// SetAccessKey sets the server access key
func (server *Server) SetAccessKey(accessKey string) {
	server.accessKey = accessKey
}

// SignatureVersion returns the server packet signature version
func (server *Server) SignatureVersion() int {
	return server.signatureVersion
}

// SetSignatureVersion sets the server packet signature version
func (server *Server) SetSignatureVersion(signatureVersion int) {
	server.signatureVersion = signatureVersion
}

// KerberosKeySize returns the server kerberos key size
func (server *Server) KerberosKeySize() int {
	return server.kerberosKeySize
}

// SetKerberosKeySize sets the server kerberos key size
func (server *Server) SetKerberosKeySize(kerberosKeySize int) {
	server.kerberosKeySize = kerberosKeySize
}

// KerberosKeySize returns the server kerberos key size
func (server *Server) FragmentSize() int16 {
	return server.fragmentSize
}

// SetKerberosKeySize sets the server kerberos key size
func (server *Server) SetFragmentSize(fragmentSize int16) {
	server.fragmentSize = fragmentSize
}

// ConnectionIDCounter gets the server connection ID counter
func (server *Server) ConnectionIDCounter() *Counter {
	return server.connectionIDCounter
}

// UsePacketCompression enables or disables packet compression
func (server *Server) UsePacketCompression(usePacketCompression bool) {
	if usePacketCompression {
		compression := ZLibCompression{}
		server.SetPacketCompression(compression.Compress)
	} else {
		compression := DummyCompression{}
		server.SetPacketCompression(compression.Compress)
	}

	server.usePacketCompression = usePacketCompression
}

// SetPacketCompression sets the packet compression function
func (server *Server) SetPacketCompression(compression func([]byte) []byte) {
	server.compressPacket = compression
}

// FindClientFromConnectionID finds a client by their Connection ID
func (server *Server) FindClientFromConnectionID(rvcid uint32) *Client {
	server.clientMutex.RLock()
	defer server.clientMutex.RUnlock()

	for _, client := range server.clients {
		if client.connectionID == rvcid {
			return client
		}
	}

	return nil
}

// FindClientFromIPAddress finds a client by their IP address
func (server *Server) FindClientFromIPAddress(ipAddress string) *Client {
	server.clientMutex.RLock()
	defer server.clientMutex.RUnlock()

	for _, client := range server.clients {
		if client.Address().String() == ipAddress {
			return client
		}
	}

	return nil
}

// Send writes data to client
func (server *Server) Send(packet PacketInterface) {
	data := packet.Payload()
	dataLength := len(data)
	fragments := int(math.Ceil(float64(dataLength) / float64(server.fragmentSize)))

	var fragmentID uint8 = 1
	for i := 0; i < fragments; i++ {
		if len(data) <= int(server.fragmentSize) {
			if packet.Type() == DataPacket {
				newData := make([]byte, len(data)+1)
				copy(newData[1:], data)
				packet.SetPayload(newData)
				server.SendFragment(packet, 0)
			} else {
				packet.SetPayload(data)
				server.SendFragment(packet, 0)
			}
			break
		} else {
			if packet.Type() == DataPacket {
				newData := make([]byte, server.fragmentSize)
				copy(newData[1:], data[:int(server.fragmentSize)-1])
				packet.SetPayload(newData)
				server.SendFragment(packet, fragmentID)

				fragmentID++
				data = data[int(server.fragmentSize)-1:]
			} else {
				packet.SetPayload(data[:int(server.fragmentSize)])
				server.SendFragment(packet, fragmentID)

				data = data[int(server.fragmentSize):]
				fragmentID++
			}
		}

		// do not overwhelm client with packets by waiting a bit before sending the next fragment
		// this should send a packet roughly every frame since the game runs at 60 fps
		// fixes the issue where loading things like leaderboards with a lot of scores would cause the client to unexpectedly DC
		if i < fragments-1 {
			time.Sleep(16 * time.Millisecond)
		}
	}
}

// SendFragment sends a packet fragment to the client
func (server *Server) SendFragment(packet PacketInterface, fragmentID uint8) {
	client := packet.Sender()

	packet.SetFragmentID(fragmentID)
	packet.SetSequenceID(uint16(client.SequenceIDCounterOut().Increment()))

	encodedPacket := packet.Bytes()

	server.SendRaw(client.Address(), encodedPacket)
}

// SendRaw writes raw packet data to the client socket
func (server *Server) SendRaw(conn *net.UDPAddr, data []byte) {
	server.Socket().WriteToUDP(data, conn)
}

// NewServer returns a new NEX server
func NewServer() *Server {
	server := &Server{
		genericEventHandles:   make(map[string][]func(PacketInterface)),
		prudpV0EventHandles:   make(map[string][]func(*PacketV0)),
		clients:               make(map[string]*Client),
		prudpVersion:          1,
		fragmentSize:          1300,
		resendTimeout:         1.5,
		pingTimeout:           5,
		signatureVersion:      0,
		flagsVersion:          1,
		checksumVersion:       1,
		kerberosKeySize:       32,
		kerberosKeyDerivation: 0,
		connectionIDCounter:   NewCounter(10),
	}

	server.UsePacketCompression(false)

	return server
}
