package protocol

import (
	"github.com/go-gl/mathgl/mgl32"
)

const (
	ShapeTypeLine uint8 = iota
	ShapeTypeBox
	ShapeTypeSphere
	ShapeTypeCircle
	ShapeTypeText
	ShapeTypeArrow
)

// Shape represents a drawable geometric or text element.
type Shape struct {
	// NetworkID uniquely identifies the shape instance for client-server synchronisation.
	NetworkID uint64
	// ShapeType is the type of the shape. It is always one of the constants listed above.
	ShapeType Optional[uint8]
	// Location is the location of the shape.
	Location Optional[mgl32.Vec3]
	// Scale is the scale of the shape.
	Scale Optional[float32]
	// Rotation is the rotation of the shape.
	Rotation Optional[mgl32.Vec3]
	// TotalTimeLeft indicates the remaining lifetime of the shape in seconds.
	// A value of zero means the shape persists indefinitely.
	TotalTimeLeft Optional[float32]
	// Colour is the colour of the shape.
	Colour Optional[int32]
	// Text contains text content for the text shape.
	Text Optional[string]
	// BoxBound defines the size dimensions of the bounding box for the box shape.
	BoxBound Optional[mgl32.Vec3]
	// LineEndLocation specifies the endpoint position for the line shape.
	LineEndLocation Optional[mgl32.Vec3]
	// ArrowHeadLength sets the length of the arrowhead for the arrow shape.
	ArrowHeadLength Optional[float32]
	// ArrowHeadRadius sets the radius of the arrowhead for the arrow shape.
	ArrowHeadRadius Optional[float32]
	// NumSegments determines the number of segments used to render circles, spheres, or arrowheads,
	// affecting visual smoothness.
	NumSegments Optional[uint8]
}

// Marshal ...
func (x *Shape) Marshal(r IO) {
	r.Varuint64(&x.NetworkID)
	OptionalFunc(r, &x.ShapeType, r.Uint8)
	OptionalFunc(r, &x.Location, r.Vec3)
	OptionalFunc(r, &x.Scale, r.Float32)
	OptionalFunc(r, &x.Rotation, r.Vec3)
	OptionalFunc(r, &x.TotalTimeLeft, r.Float32)
	OptionalFunc(r, &x.Colour, r.Int32)
	OptionalFunc(r, &x.Text, r.String)
	OptionalFunc(r, &x.BoxBound, r.Vec3)
	OptionalFunc(r, &x.LineEndLocation, r.Vec3)
	OptionalFunc(r, &x.ArrowHeadLength, r.Float32)
	OptionalFunc(r, &x.ArrowHeadRadius, r.Float32)
	OptionalFunc(r, &x.NumSegments, r.Uint8)
}
