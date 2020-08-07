package rcon

import "fmt"

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

	packet, err := c.inner.ReadPacket()
	if err != nil {
		return "", err
	} else if packet.Header.Challenge != execPacket.Header.Challenge {
		return "", ErrInvalidRead
	} else if packet.Header.Type != ResponseValue {
		return "", ErrInvalidRead
	}

	return packet.Body, nil
}

func (c *Client) Close() error {
	return c.inner.Close()
}
