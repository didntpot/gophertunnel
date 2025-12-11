package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientBoundDataStore is sent by the server to the client to update data store properties.
type ClientBoundDataStore struct {
	// Updates is a list of data store actions to apply.
	Updates []protocol.DataStoreAction
}

// ID ...
func (*ClientBoundDataStore) ID() uint32 {
	return IDClientBoundDataStore
}

func (pk *ClientBoundDataStore) Marshal(io protocol.IO) {
	protocol.Slice(io, &pk.Updates)
}
