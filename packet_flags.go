package nex

const (
	// FlagAck is the ID for the PRUDP Ack Flag
	FlagAck uint8 = 0x1

	// FlagReliable is the ID for the PRUDP Reliable Flag
	FlagReliable uint8 = 0x2

	// FlagNeedsAck is the ID for the PRUDP NeedsAck Flag
	FlagNeedsAck uint8 = 0x4

	// FlagHasSize is the ID for the PRUDP HasSize Flag
	FlagHasSize uint8 = 0x8
)
