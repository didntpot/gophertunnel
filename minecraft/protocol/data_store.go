package protocol

const (
	DataStoreActionTypeUpdate = iota
	DataStoreActionTypeChange
	DataStoreActionTypeRemoval
)

const (
	DataStoreValueTypeDouble = iota
	DataStoreValueTypeBool
	DataStoreValueTypeString
)

// DataStoreUpdate represents an update to a data store property.
type DataStoreUpdate struct {
	// DataStoreName is the name of the data store.
	DataStoreName string
	// Property is the property being updated.
	Property string
	// Path is the path to the value being updated.
	Path string
	// Data is the value being set. Can be float64, bool, or string.
	Data any
	// UpdateCount is the number of times this property has been updated.
	UpdateCount int32
}

// Marshal encodes/decodes a DataStoreUpdate.
func (x *DataStoreUpdate) Marshal(r IO) {
	r.String(&x.DataStoreName)
	r.String(&x.Property)
	r.String(&x.Path)
	r.DataStoreValue(&x.Data)
	r.Int32(&x.UpdateCount)
}

// DataStoreChange represents a change notification to a data store property.
type DataStoreChange struct {
	// DataStoreName is the name of the data store.
	DataStoreName string
	// Property is the property that changed.
	Property string
	// UpdateCount is the number of times this property has been updated.
	UpdateCount int32
	// NewValue is the new value. Can be float64, bool, or string.
	NewValue any
}

// Marshal encodes/decodes a DataStoreChange.
func (x *DataStoreChange) Marshal(r IO) {
	r.String(&x.DataStoreName)
	r.String(&x.Property)
	r.Int32(&x.UpdateCount)
	r.DataStoreValue(&x.NewValue)
}

// DataStoreRemoval represents removal of a data store.
type DataStoreRemoval struct {
	// DataStoreName is the name of the data store being removed.
	DataStoreName string
}

// Marshal encodes/decodes a DataStoreRemoval.
func (x *DataStoreRemoval) Marshal(r IO) {
	r.String(&x.DataStoreName)
}

// DataStoreAction is a union type for data store actions.
type DataStoreAction struct {
	// ActionType is the type of action. One of DataStoreActionType* constants.
	ActionType uint32
	// Update is set when ActionType is DataStoreActionTypeUpdate.
	Update DataStoreUpdate
	// Change is set when ActionType is DataStoreActionTypeChange.
	Change DataStoreChange
	// Removal is set when ActionType is DataStoreActionTypeRemoval.
	Removal DataStoreRemoval
}

// Marshal encodes/decodes a DataStoreAction.
func (x *DataStoreAction) Marshal(r IO) {
	r.Varuint32(&x.ActionType)
	switch x.ActionType {
	case DataStoreActionTypeUpdate:
		Single(r, &x.Update)
	case DataStoreActionTypeChange:
		Single(r, &x.Change)
	case DataStoreActionTypeRemoval:
		Single(r, &x.Removal)
	default:
		r.UnknownEnumOption(x.ActionType, "data store action type")
	}
}
