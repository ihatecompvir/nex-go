package nex

// PacketInterface implements all Packet methods
type PacketInterface interface {
	Sender() *Client
	SetVersion(version uint8)
	Version() uint8
	SetSource(source uint8)
	Source() uint8
	SetDestination(destination uint8)
	Destination() uint8
	SetType(packetType uint8)
	Type() uint8
	SetFlags(bitmask uint8)
	Flags() uint8
	HasFlag(flag uint8) bool
	AddFlag(flag uint8)
	ClearFlag(flag uint8)
	SetSessionID(sessionID uint8)
	SessionID() uint8
	SetSignature(signature []byte)
	Signature() []byte
	SetSequenceID(sequenceID uint16)
	SequenceID() uint16
	SetConnectionSignature(connectionSignature []byte)
	ConnectionSignature() []byte
	SetFragmentID(fragmentID uint8)
	FragmentID() uint8
	SetPayload(payload []byte)
	Payload() []byte
	RMCRequest() RMCRequest
	Bytes() []byte
}
