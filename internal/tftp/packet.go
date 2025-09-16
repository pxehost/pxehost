package tftp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type parseError string

func (e parseError) Error() string { return string(e) }

var (
	ErrShortPacket        = parseError("short packet")
	ErrOptionWithoutValue = parseError("option without value")
	ErrShortDATA          = parseError("short DATA")
	ErrBadACKLength       = parseError("bad ACK length")
	ErrShortERROR         = parseError("short ERROR")
	ErrUnknownOpcode      = parseError("unknown opcode")
	ErrExpectedZStr       = parseError("expected zstr")
	ErrUnterminatedZStr   = parseError("unterminated zstr")
)

type Opcode uint16

const (
	RRQ   Opcode = 1
	WRQ   Opcode = 2
	DATA  Opcode = 3
	ACK   Opcode = 4
	ERROR Opcode = 5
	OACK  Opcode = 6
)

type Packet interface {
	Op() Opcode
}

type ReadReq struct {
	Write    bool // true=WRQ, false=RRQ
	Filename string
	Mode     string            // usually "octet" or "netascii"
	Options  map[string]string // e.g. blksize, tsize, timeout
}

func (p *ReadReq) Op() Opcode {
	return RRQ
}

type WriteReq struct {
	Filename string
	Mode     string            // usually "octet" or "netascii"
	Options  map[string]string // e.g. blksize, tsize, timeout
}

func (p *WriteReq) Op() Opcode {
	return WRQ
}

type Data struct {
	Block uint16
	Data  []byte
}

func (p *Data) Op() Opcode { return DATA }

type Ack struct {
	Block uint16
}

func (p *Ack) Op() Opcode { return ACK }

type Err struct {
	Code    uint16
	Message string
}

func (p *Err) Op() Opcode { return ERROR }

type OAck struct {
	Options map[string]string
}

func (p *OAck) Op() Opcode { return OACK }

func Serialize(p Packet) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write opcode first
	if err := binary.Write(buf, binary.BigEndian, p.Op()); err != nil {
		return nil, fmt.Errorf("write opcode: %w", err)
	}

	switch v := p.(type) {
	case *ReadReq:
		if _, err := buf.WriteString(v.Filename); err != nil {
			return nil, err
		}
		buf.WriteByte(0)
		if _, err := buf.WriteString(v.Mode); err != nil {
			return nil, err
		}
		buf.WriteByte(0)
		for k, val := range v.Options {
			if _, err := buf.WriteString(k); err != nil {
				return nil, err
			}
			buf.WriteByte(0)
			if _, err := buf.WriteString(val); err != nil {
				return nil, err
			}
			buf.WriteByte(0)
		}

	case *WriteReq:
		if _, err := buf.WriteString(v.Filename); err != nil {
			return nil, err
		}
		buf.WriteByte(0)
		if _, err := buf.WriteString(v.Mode); err != nil {
			return nil, err
		}
		buf.WriteByte(0)
		for k, val := range v.Options {
			if _, err := buf.WriteString(k); err != nil {
				return nil, err
			}
			buf.WriteByte(0)
			if _, err := buf.WriteString(val); err != nil {
				return nil, err
			}
			buf.WriteByte(0)
		}

	case *Data:
		if err := binary.Write(buf, binary.BigEndian, v.Block); err != nil {
			return nil, err
		}
		if _, err := buf.Write(v.Data); err != nil {
			return nil, err
		}

	case *Ack:
		if err := binary.Write(buf, binary.BigEndian, v.Block); err != nil {
			return nil, err
		}

	case *Err:
		if err := binary.Write(buf, binary.BigEndian, v.Code); err != nil {
			return nil, err
		}
		if _, err := buf.WriteString(v.Message); err != nil {
			return nil, err
		}
		buf.WriteByte(0)

	case *OAck:
		for k, val := range v.Options {
			if _, err := buf.WriteString(k); err != nil {
				return nil, err
			}
			buf.WriteByte(0)
			if _, err := buf.WriteString(val); err != nil {
				return nil, err
			}
			buf.WriteByte(0)
		}

	default:
		return nil, ErrUnknownOpcode
	}

	return buf.Bytes(), nil
}

// Parse decodes a single TFTP packet from buf.
// It returns a concrete type implementing Packet.
func ParsePacket(buf []byte) (Packet, error) {
	if len(buf) < 2 {
		return nil, ErrShortPacket
	}
	op := Opcode(binary.BigEndian.Uint16(buf[:2]))

	switch op {
	case RRQ, WRQ:
		i := 2
		filename, n, err := readZ(buf, i)
		if err != nil {
			return nil, err
		}
		i = n
		mode, n, err := readZ(buf, i)
		if err != nil {
			return nil, err
		}
		i = n
		opts := map[string]string{}
		for i < len(buf) {
			k, n1, err := readZ(buf, i)
			if err != nil {
				return nil, err
			}
			i = n1
			if i >= len(buf) {
				return nil, ErrOptionWithoutValue
			}
			v, n2, err := readZ(buf, i)
			if err != nil {
				return nil, err
			}
			i = n2
			opts[strToLowerASCII(k)] = strToLowerASCII(v)
		}
		if op == RRQ {
			return &ReadReq{
				Filename: filename,
				Mode:     strToLowerASCII(mode),
				Options:  opts,
			}, nil
		} else {
			return &WriteReq{
				Filename: filename,
				Mode:     strToLowerASCII(mode),
				Options:  opts,
			}, nil
		}

	case DATA:
		if len(buf) < 4 {
			return nil, ErrShortDATA
		}
		block := binary.BigEndian.Uint16(buf[2:4])
		return &Data{Block: block, Data: append([]byte(nil), buf[4:]...)}, nil

	case ACK:
		if len(buf) != 4 {
			return nil, ErrBadACKLength
		}
		block := binary.BigEndian.Uint16(buf[2:4])
		return &Ack{Block: block}, nil

	case ERROR:
		if len(buf) < 5 {
			return nil, ErrShortERROR
		}
		code := binary.BigEndian.Uint16(buf[2:4])
		msg, _, err := readZ(buf, 4)
		if err != nil {
			return nil, err
		}
		return &Err{Code: code, Message: msg}, nil

	case OACK:
		i := 2
		opts := map[string]string{}
		for i < len(buf) {
			k, n1, err := readZ(buf, i)
			if err != nil {
				return nil, err
			}
			i = n1
			if i >= len(buf) {
				return nil, ErrOptionWithoutValue
			}
			v, n2, err := readZ(buf, i)
			if err != nil {
				return nil, err
			}
			i = n2
			opts[strToLowerASCII(k)] = strToLowerASCII(v)
		}
		return &OAck{Options: opts}, nil
	default:
		return nil, ErrUnknownOpcode
	}
}

func readZ(b []byte, i int) (string, int, error) {
	if i >= len(b) {
		return "", 0, ErrExpectedZStr
	}
	j := i
	for j < len(b) && b[j] != 0 {
		j++
	}
	if j >= len(b) {
		return "", 0, ErrUnterminatedZStr
	}
	return string(b[i:j]), j + 1, nil
}

// strToLowerASCII lowers A-Z without locale allocations.
func strToLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
