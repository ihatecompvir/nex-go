package nex

const (
	// SynPacket is the ID for the PRUDP Syn Packet type
	SynPacket uint8 = 0x0

	// ConnectPacket is the ID for the PRUDP Connect Packet type
	ConnectPacket uint8 = 0x1

	// DataPacket is the ID for the PRUDP Data Packet type
	DataPacket uint8 = 0x2

	// DisconnectPacket is the ID for the PRUDP Disconnect Packet type
	DisconnectPacket uint8 = 0x3

	// PingPacket is the ID for the PRUDP Ping Packet type
	PingPacket uint8 = 0x4
)

var validTypes = map[uint8]bool{
	SynPacket:        true,
	ConnectPacket:    true,
	DataPacket:       true,
	DisconnectPacket: true,
	PingPacket:       true,
}
