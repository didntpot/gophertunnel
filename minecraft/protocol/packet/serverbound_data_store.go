package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerBoundDataStore is sent by the client to the server to update a data store property.
type ServerBoundDataStore struct {
	// Update is the data store update to apply.
	Update protocol.DataStoreUpdate
}

// ID ...
func (*ServerBoundDataStore) ID() uint32 {
	return IDServerBoundDataStore
}

func (pk *ServerBoundDataStore) Marshal(io protocol.IO) {
	protocol.Single(io, &pk.Update)
}
