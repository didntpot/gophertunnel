package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// DebugShapesUpdate is a packet used by the scripting API to inform the client
// about new, removed, or modified debug shapes for rendering purposes.
type DebugShapesUpdate struct {
	// Shapes contains the list of shapes that have been added, removed, or modified.
	Shapes []protocol.Shape
}

// ID ...
func (*DebugShapesUpdate) ID() uint32 {
	return IDDebugShapesUpdate
}

func (pk *DebugShapesUpdate) Marshal(io protocol.IO) {
	protocol.Slice(io, &pk.Shapes)
}
