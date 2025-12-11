package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	AnimateActionSwingArm = iota + 1
	_
	AnimateActionStopSleep
	AnimateActionCriticalHit
	AnimateActionMagicCriticalHit
)

const (
	AnimateActionRowRight = iota + 128
	AnimateActionRowLeft
)

const (
	SwingSourceNone      = "none"
	SwingSourceBuild     = "build"
	SwingSourceMine      = "mine"
	SwingSourceInteract  = "interact"
	SwingSourceAttack    = "attack"
	SwingSourceUseItem   = "useitem"
	SwingSourceThrowItem = "throwitem"
	SwingSourceDropItem  = "dropitem"
	SwingSourceEvent     = "event"
)

// Animate is sent by the server to send a player animation from one player to all viewers of that player. It
// is used for a couple of actions, such as arm swimming and critical hits.
type Animate struct {
	// ActionType is the ID of the animation action to execute. It is one of the action type constants that
	// may be found above.
	ActionType int32
	// EntityRuntimeID is the runtime ID of the player that the animation should be played upon. The runtime
	// ID is unique for each world session, and entities are generally identified in packets using this
	// runtime ID.
	EntityRuntimeID uint64
	// Data is additional data for the animation.
	Data float32
	// SwingSource indicates the source of the arm swing animation. It is one of the SwingSource* constants.
	// This field is optional and is only present when not empty.
	SwingSource string
}

// ID ...
func (*Animate) ID() uint32 {
	return IDAnimate
}

func (pk *Animate) Marshal(io protocol.IO) {
	action := byte(pk.ActionType)
	io.Uint8(&action)
	pk.ActionType = int32(action)
	io.Varuint64(&pk.EntityRuntimeID)
	io.Float32(&pk.Data)
	hasSwingSource := pk.SwingSource != "" && pk.SwingSource != SwingSourceNone
	io.Bool(&hasSwingSource)
	if hasSwingSource {
		io.String(&pk.SwingSource)
	}
}
