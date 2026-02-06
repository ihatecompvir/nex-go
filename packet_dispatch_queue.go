package nex

import (
	"sync"
)

// PacketDispatchQueue reorders incoming packets by SequenceID so they are
// processed in strict numerical order, regardless of UDP arrival order.
type PacketDispatchQueue struct {
	mutex                  sync.Mutex
	queue                  map[uint16]PacketInterface
	nextExpectedSequenceID uint16
}

// Queue adds a packet to the dispatch queue indexed by its SequenceID.
func (pdq *PacketDispatchQueue) Queue(packet PacketInterface) {
	pdq.mutex.Lock()
	defer pdq.mutex.Unlock()

	pdq.queue[packet.SequenceID()] = packet
}

// GetNextToDispatch returns the next packet in sequence order, or nil if
// the next expected packet has not yet arrived.
func (pdq *PacketDispatchQueue) GetNextToDispatch() PacketInterface {
	pdq.mutex.Lock()
	defer pdq.mutex.Unlock()

	packet, ok := pdq.queue[pdq.nextExpectedSequenceID]
	if !ok {
		return nil
	}

	return packet
}

// Dispatched marks the current packet as processed, removes it from the
// queue, and advances the expected sequence ID.
func (pdq *PacketDispatchQueue) Dispatched(packet PacketInterface) {
	pdq.mutex.Lock()
	defer pdq.mutex.Unlock()

	delete(pdq.queue, packet.SequenceID())
	pdq.nextExpectedSequenceID++
}

// NewPacketDispatchQueue returns a new PacketDispatchQueue with the given
// starting sequence ID.
func NewPacketDispatchQueue(startSequenceID uint16) *PacketDispatchQueue {
	return &PacketDispatchQueue{
		queue:                  make(map[uint16]PacketInterface),
		nextExpectedSequenceID: startSequenceID,
	}
}
