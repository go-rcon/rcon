package rcon

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
)

type Conn struct {
	inner net.Conn
}

func Dial(addr string) (*Conn, error) {
	inner, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &Conn{
		inner: inner,
	}, nil
}

func (c *Conn) Close() error {
	return c.inner.Close()
}

func (c *Conn) WritePacket(packet *Packet) error {
	_, err := c.inner.Write(packet.Compile())
	return err
}

func (c *Conn) ReadPacket() (*Packet, error) {
	var header Header

	if err := binary.Read(c.inner, binary.LittleEndian, &header.Size); nil != err {
		return nil, err
	} else if err = binary.Read(c.inner, binary.LittleEndian, &header.Challenge); nil != err {
		return nil, err
	} else if err = binary.Read(c.inner, binary.LittleEndian, &header.Type); nil != err {
		return nil, err
	}

	if header.Size > 4096 {
		return nil, ErrInvalidRead
	}

	body := make([]byte, header.Size-int32(PacketHeaderSize))
	_, err := io.ReadFull(c.inner, body)
	if err != nil {
		return nil, err
	}

	return &Packet{
		Header: header,
		Body:   strings.TrimRight(string(body), TerminationSequence),
	}, nil
}
