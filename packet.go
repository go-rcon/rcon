package rcon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
)

const (
	PacketPaddingSize uint8 = 2 // Size of Packet's padding.
	PacketHeaderSize  uint8 = 8 // Size of Packet's header.
)

const (
	TerminationSequence = "\x00" // Null empty ASCII string suffix.
)

// Packet type constants.
// https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Packet_Type
type PacketType int32

const (
	Exec          PacketType = 2
	Auth          PacketType = 3
	AuthResponse  PacketType = 2
	ResponseValue PacketType = 0
)

// Rcon package errors.
var (
	ErrInvalidWrite        = errors.New("Failed to write the payload correctly to remote connection.")
	ErrInvalidRead         = errors.New("Failed to read the response correctly from remote connection.")
	ErrInvalidChallenge    = errors.New("Server failed to mirror request challenge.")
	ErrUnauthorizedRequest = errors.New("Client not authorized to remote server.")
	ErrFailedAuthorization = errors.New("Failed to authorize to the remote server.")
)

type Header struct {
	Size      int32      // The size of the payload.
	Challenge int32      // The challenge ths server should mirror.
	Type      PacketType // The type of request being sent.
}

type Packet struct {
	Header Header // Packet header.
	Body   string // Body of packet.
}

// NewPacket returns a pointer to a new Packet type.
func NewPacket(typ PacketType, body string) (packet *Packet) {
	// Create a random challenge for the server to mirror in its response.
	//
	// TODO: it is theoretically possible to get -1 here which would break an
	// Auth response. We should use rand.Int31 and ensure it's in little endian.
	challenge := rand.Int31()

	size := int32(len([]byte(body)) + int(PacketHeaderSize+PacketPaddingSize))
	return &Packet{Header{size, challenge, typ}, body}
}

// Compile converts a packets header and body into its appropriate byte array
// payload, returning an error if the binary packages Write method fails to
// write the header bytes in their little endian byte order.
func (p Packet) Compile() []byte {
	var size int32 = p.Header.Size
	var buffer bytes.Buffer
	var padding [PacketPaddingSize]byte

	binary.Write(&buffer, binary.LittleEndian, size)
	binary.Write(&buffer, binary.LittleEndian, p.Header.Challenge)
	binary.Write(&buffer, binary.LittleEndian, p.Header.Type)

	buffer.WriteString(p.Body)
	buffer.Write(padding[:])

	return buffer.Bytes()
}
