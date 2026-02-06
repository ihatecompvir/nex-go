package nex

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"log"
)

// PacketV0 reresents a PRUDPv0 packet
type PacketV0 struct {
	Packet
	checksum uint32
}

// SetChecksum sets the packet checksum
func (packet *PacketV0) SetChecksum(checksum uint32) {
	packet.checksum = checksum
}

// Checksum returns the packet checksum
func (packet *PacketV0) Checksum() uint32 {
	return packet.checksum
}

// Decode decodes the packet
func (packet *PacketV0) Decode() error {

	if len(packet.Data()) < 9 {
		return errors.New("[PRUDPv0] Packet length less than header minimum")
	}

	var checksumSize int
	var payloadSize uint16
	var typeFlags uint8

	checksumSize = 1

	stream := NewStreamIn(packet.Data(), packet.Sender().Server())

	packet.SetSource(stream.ReadUInt8())
	packet.SetDestination(stream.ReadUInt8())

	typeFlags = stream.ReadUInt8()

	packet.SetSessionID(stream.ReadUInt8())
	packet.SetSignature(stream.ReadBytesNext(4))
	packet.SetSequenceID(stream.ReadUInt16LE())

	packet.SetType(typeFlags & 7)
	packet.SetFlags(typeFlags >> 3)

	if _, ok := validTypes[packet.Type()]; !ok {
		return errors.New("[PRUDPv0] Packet type not valid type")
	}

	if packet.Type() == SynPacket || packet.Type() == ConnectPacket {
		if len(packet.Data()[stream.ByteOffset():]) < 4 {
			return errors.New("[PRUDPv0] Packet specific data not large enough for connection signature")
		}

		packet.SetConnectionSignature(stream.ReadBytesNext(4))
	}

	if packet.Type() == DataPacket {
		if len(packet.Data()[stream.ByteOffset():]) < 1 {
			return errors.New("[PRUDPv0] Packet specific data not large enough for fragment ID")
		}

		packet.SetFragmentID(stream.ReadUInt8())
	}

	if packet.HasFlag(FlagHasSize) {
		if len(packet.Data()[stream.ByteOffset():]) < 2 {
			return errors.New("[PRUDPv0] Packet specific data not large enough for payload size")
		}

		payloadSize = stream.ReadUInt16LE()
	} else {
		payloadSize = uint16(len(packet.data) - int(stream.ByteOffset()) - checksumSize)
	}

	if payloadSize > 0 {
		if len(packet.Data()[stream.ByteOffset():]) < int(payloadSize) {
			return errors.New("[PRUDPv0] Packet data length less than payload length")
		}

		payloadCrypted := stream.ReadBytesNext(int64(payloadSize))

		packet.SetPayload(payloadCrypted)

		if packet.Type() == DataPacket || packet.Type() == DisconnectPacket {
			ciphered := make([]byte, payloadSize)

			packet.Sender().Decipher().XORKeyStream(ciphered, payloadCrypted)
			newArray := make([]byte, len(ciphered)-1)
			copy(newArray, ciphered[1:])
			if newArray[0] == 0x78 && newArray[1] == 0x9C {
				zlib := ZLibCompression{}
				newArray = zlib.Decompress(newArray)
			}

			if packet.Type() == DataPacket {
				if packet.FragmentID() > 0 {
					packet.sender.StoreFragment(packet.FragmentID(), newArray)
					packet.SetIsPartialFragment(true)
				} else if packet.sender.HasFragments() {
					newArray = packet.sender.AssembleFragments(newArray)
					packet.SetPayload(newArray)
				}
			}

			if !packet.isPartialFragment {
				request, err := NewRMCRequest(newArray)

				if err != nil {
					log.Println("[PRUDPv0] Error parsing RMC request: " + err.Error())
				}

				packet.rmcRequest = request
			}
		}
	}

	if len(packet.Data()[stream.ByteOffset():]) < int(checksumSize) {
		return errors.New("[PRUDPv0] Packet data length less than checksum length")
	}

	if checksumSize == 1 {
		packet.SetChecksum(uint32(stream.ReadUInt8()))
	} else {
		packet.SetChecksum(stream.ReadUInt32LE())
	}

	packetBody := stream.Bytes()

	calculatedChecksum := packet.calculateChecksum(packetBody[:len(packetBody)-checksumSize])

	if calculatedChecksum != packet.Checksum() {
		if debugNetwork.Load() {
			log.Printf("[DIAG] Checksum mismatch from %s: calculated=0x%X received=0x%X type=%d seq=%d len=%d\n",
				packet.Sender().Address().String(), calculatedChecksum, packet.Checksum(),
				packet.Type(), packet.SequenceID(), len(packetBody))
		} else {
			log.Println("[ERROR] Calculated checksum did not match")
		}
	}

	return nil
}

// Bytes encodes the packet and returns a byte array
func (packet *PacketV0) Bytes() []byte {
	if packet.Type() == DataPacket {

		if packet.HasFlag(FlagAck) {
			packet.SetPayload([]byte{})
		} else {
			payload := packet.Payload()

			if payload != nil || len(payload) > 0 {
				payloadSize := len(payload)

				encrypted := make([]byte, payloadSize)
				packet.Sender().Cipher().XORKeyStream(encrypted, payload)

				packet.SetPayload(encrypted)
			}
		}
	}

	var typeFlags uint8
	typeFlags = packet.Type()&7 | packet.Flags()<<3

	stream := NewStreamOut(packet.Sender().Server())
	packetSignature := packet.calculateSignature()

	stream.WriteUInt8(packet.Source())
	stream.WriteUInt8(packet.Destination())
	stream.WriteUInt8(typeFlags)
	stream.WriteUInt8(packet.SessionID())
	stream.Grow(int64(len(packetSignature)))
	stream.WriteBytesNext(packetSignature)
	stream.WriteUInt16LE(packet.SequenceID())

	options := packet.encodeOptions()
	optionsLength := len(options)

	if optionsLength > 0 {
		stream.Grow(int64(optionsLength))
		stream.WriteBytesNext(options)
	}

	payload := packet.Payload()

	if payload != nil && len(payload) > 0 {
		stream.Grow(int64(len(payload)))
		stream.WriteBytesNext(payload)
	}

	checksum := packet.calculateChecksum(stream.Bytes())

	if packet.Sender().Server().ChecksumVersion() == 0 {
		stream.WriteUInt32LE(checksum)
	} else {
		stream.WriteUInt8(uint8(checksum))
	}

	return stream.Bytes()
}

func (packet *PacketV0) calculateSignature() []byte {
	if packet.Type() == DataPacket || packet.Type() == DisconnectPacket {
		payload := NewStreamOut(packet.Sender().Server())
		sessionKey := packet.Sender().SessionKey()
		if sessionKey != nil {
			payload.Grow(int64(len(sessionKey)))
			payload.WriteBytesNext(sessionKey)
		}
		payload.WriteUInt16LE(packet.sequenceID)
		payload.Grow(1)
		payload.WriteByteNext(packet.fragmentID)
		pktpay := packet.Payload()
		if pktpay != nil && len(pktpay) > 0 {
			payload.Grow(int64(len(pktpay)))
			payload.WriteBytesNext(pktpay)
		}

		key := packet.Sender().SignatureKey()
		cipher := hmac.New(md5.New, key)
		cipher.Write(packet.Sender().ClientConnectionSignature())

		// a hack but this bypasses the HMAC stuff that is in Nintendo's PRUDP
		// Quazal Rendez-vous just uses a random number here, but using the clients randomly generated number works too :)
		return packet.Sender().ClientConnectionSignature()
	} else {
		clientConnectionSignature := packet.Sender().ClientConnectionSignature()

		if clientConnectionSignature != nil {
			return clientConnectionSignature
		}
	}

	return []byte{}
}

func (packet *PacketV0) encodeOptions() []byte {
	stream := NewStreamOut(packet.Sender().Server())

	if packet.Type() == SynPacket {
		stream.Grow(4)
		stream.WriteBytesNext(packet.Sender().ServerConnectionSignature())
	}

	if packet.Type() == ConnectPacket {
		stream.Grow(4)
		stream.WriteBytesNext(packet.Sender().ClientConnectionSignature())
	}

	if packet.Type() == DataPacket {
		stream.WriteUInt8(packet.FragmentID())
	}

	return stream.Bytes()
}

func (packet *PacketV0) calculateChecksum(data []byte) uint32 {
	signatureBase := packet.Sender().SignatureBase()
	steps := len(data) / 4
	var temp uint32

	for i := 0; i < steps; i++ {
		offset := i * 4
		temp += binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	temp &= 0xFFFFFFFF

	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, temp)

	checksum := signatureBase
	checksum += sum(data[len(data) & ^3:])
	checksum += sum(buff)

	return uint32(checksum & 0xFF)
}

// NewPacketV0 returns a new PRUDPv0 packet
func NewPacketV0(client *Client, data []byte) (*PacketV0, error) {
	packet := NewPacket(client, data)
	packetv0 := PacketV0{Packet: packet}

	if data != nil {
		err := packetv0.Decode()

		if err != nil {
			return &PacketV0{}, errors.New("[PRUDPv0] Error decoding packet data: " + err.Error())
		}
	}

	return &packetv0, nil
}
