package rcon

import (
	"bytes"
	"fmt"
)

type Client struct {
	inner *Conn
}

func NewClient(addr, password string) (*Client, error) {
	inner, err := Dial(addr)
	if err != nil {
		return nil, err
	}

	authPacket := NewPacket(Auth, password)
	err = inner.WritePacket(authPacket)
	if err != nil {
		return nil, err
	}

	packet, err := inner.ReadPacket()
	if err != nil {
		return nil, err
	}

	if packet.Header.Type == ResponseValue {
		packet, err = inner.ReadPacket()
		if err != nil {
			return nil, err
		}
	}

	if packet.Header.Challenge != authPacket.Header.Challenge {
		fmt.Println("invalid auth resp challenge")
		return nil, ErrFailedAuthorization
	} else if packet.Header.Type != AuthResponse {
		fmt.Println("invalid auth resp type")
		return nil, ErrFailedAuthorization
	}

	return &Client{inner: inner}, nil
}

func (c *Client) RunCommand(cmd string) (string, error) {
	execPacket := NewPacket(Exec, cmd)
	err := c.inner.WritePacket(execPacket)
	if err != nil {
		return "", err
	}

	// We use a sentinel packet to figure out when we're done. The help command
	// should always succeed and *should* be under 4096 characters so it works
	// well for this use case.
	sentinelPacket := NewPacket(Exec, "help")

	var out bytes.Buffer
	var first bool = true

	for {
		packet, err := c.inner.ReadPacket()
		if err != nil {
			return "", err
		} else if packet.Header.Challenge == sentinelPacket.Header.Challenge {
			break
		} else if packet.Header.Challenge != execPacket.Header.Challenge {
			return "", ErrInvalidRead
		} else if packet.Header.Type != ResponseValue {
			return "", ErrInvalidRead
		}

		out.WriteString(packet.Body)

		// If we got to this point, we should be done, but there could be a
		// leftover sentinel packet to read, so make sure we handle that.
		if packet.Header.Size != 4106 {
			if !first {
				packet, err := c.inner.ReadPacket()
				if err != nil {
					return "", err
				} else if packet.Header.Challenge != sentinelPacket.Header.Challenge {
					return "", ErrInvalidRead
				}
			}

			break
		}

		// If this was our first loop iteration, write our sentinel packet to
		// the stream so we know when we can stop looping.
		if first {
			err = c.inner.WritePacket(sentinelPacket)
			if err != nil {
				return "", err
			}
			first = false
		}
	}

	return out.String(), nil
}

func (c *Client) Close() error {
	return c.inner.Close()
}
