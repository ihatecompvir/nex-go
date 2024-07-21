package nex

import (
	"reflect"

	crunch "github.com/superwhiskers/crunch/v3"
)

// StreamOut is an abstraction of github.com/superwhiskers/crunch with nex type support
type StreamOut struct {
	*crunch.Buffer
	Server *Server
}

// WriteUInt8 writes a uint8
func (stream *StreamOut) WriteUInt8(u8 uint8) {
	stream.Grow(1)
	stream.WriteByteNext(byte(u8))
}

// WriteUInt16LE writes a uint16 as LE
func (stream *StreamOut) WriteUInt16LE(u16 uint16) {
	stream.Grow(2)
	stream.WriteU16LENext([]uint16{u16})
}

// WriteUInt32LE writes a uint32 as LE
func (stream *StreamOut) WriteUInt32LE(u32 uint32) {
	stream.Grow(4)
	stream.WriteU32LENext([]uint32{u32})
}

// WriteUInt64LE writes a uint64 as LE
func (stream *StreamOut) WriteUInt64LE(u64 uint64) {
	stream.Grow(8)
	stream.WriteU64LENext([]uint64{u64})
}

// WriteString writes a NEX string type
func (stream *StreamOut) WriteString(str string) {
	strLength := len(str)

	stream.Grow(int64((strLength * 2) + 1))
	stream.WriteUInt16LE(uint16((strLength * 2) + 1))
	stream.WriteBytesNext([]byte(str))
	stream.WriteBytesNext(make([]byte, len(str)+1))
}

func (stream *StreamOut) WriteBufferString(str string) {
	str = str + "\x00"
	strLength := len(str)

	stream.Grow(int64(strLength))
	stream.WriteUInt32LE(uint32(strLength))
	stream.WriteBytesNext([]byte(str))
}

// WriteBuffer writes a NEX Buffer type
func (stream *StreamOut) WriteBuffer(data []byte) {
	dataLength := len(data)

	stream.WriteUInt32LE(uint32(dataLength))
	stream.Grow(int64(dataLength))
	stream.WriteBytesNext(data)
}

// WriteStructure writes a nex Structure type
func (stream *StreamOut) WriteStructure(structure StructureInterface) {
	content := structure.Bytes(NewStreamOut(stream.Server))

	if stream.Server.NexVersion() >= 3 {
		stream.WriteUInt8(1) // version
		stream.WriteUInt32LE(uint32(len(content)))
	}

	stream.Grow(int64(len(content)))
	stream.WriteBytesNext(content)
}

// WriteListUInt8 writes a list of uint8 types
func (stream *StreamOut) WriteListUInt8(list []uint8) {
	stream.WriteUInt32LE(uint32(len(list)))

	for i := 0; i < len(list); i++ {
		stream.WriteUInt8(list[i])
	}
}

// WriteListUInt16LE writes a list of uint16 types
func (stream *StreamOut) WriteListUInt16LE(list []uint16) {
	stream.WriteUInt32LE(uint32(len(list)))

	for i := 0; i < len(list); i++ {
		stream.WriteUInt16LE(list[i])
	}
}

// WriteListUInt32LE writes a list of uint32 types
func (stream *StreamOut) WriteListUInt32LE(list []uint32) {
	stream.WriteUInt32LE(uint32(len(list)))

	for i := 0; i < len(list); i++ {
		stream.WriteUInt32LE(list[i])
	}
}

// WriteListUInt64LE writes a list of uint64 types
func (stream *StreamOut) WriteListUInt64LE(list []uint64) {
	stream.WriteUInt32LE(uint32(len(list)))

	for i := 0; i < len(list); i++ {
		stream.WriteUInt64LE(list[i])
	}
}

// WriteListStructure writes a list of Structure types
func (stream *StreamOut) WriteListStructure(structures interface{}) {
	// TODO:
	// Find a better solution that doesn't use reflect

	slice := reflect.ValueOf(structures)
	count := slice.Len()

	stream.WriteUInt32LE(uint32(count))

	for i := 0; i < count; i++ {
		structure := slice.Index(i).Interface().(StructureInterface)
		stream.WriteStructure(structure)
	}
}

// NewStreamOut returns a new nex output stream
func NewStreamOut(server *Server) *StreamOut {
	return &StreamOut{
		Buffer: crunch.NewBuffer(),
		Server: server,
	}
}

// NewStreamIn returns a new NEX input stream
func NewStream() *StreamOut {
	var array []byte
	return &StreamOut{
		Buffer: crunch.NewBuffer(array),
		Server: nil,
	}
}
