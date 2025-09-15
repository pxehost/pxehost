package testutil

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// MockConn is a test double implementing net.PacketConn with pluggable behaviors.
type MockConn struct {
	mu sync.Mutex

	// Function hooks; if nil, sensible defaults are used.
	ReadFromFunc         func(b []byte) (int, net.Addr, error)
	WriteToFunc          func(b []byte, addr net.Addr) (int, error)
	SetDeadlineFunc      func(t time.Time) error
	SetWriteDeadlineFunc func(t time.Time) error
	SetReadDeadlineFunc  func(t time.Time) error
	LocalAddrFunc        func() net.Addr
	CloseFunc            func() error

	// Optional state to help simple tests without providing hooks.
	Local  net.Addr
	Closed bool
}

func (m *MockConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if f := m.ReadFromFunc; f != nil {
		return f(b)
	}
	return 0, nil, fmt.Errorf("MockConn.ReadFrom: %w", errors.New("not implemented"))
}

func (m *MockConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if f := m.WriteToFunc; f != nil {
		return f(b, addr)
	}
	return len(b), nil
}

func (m *MockConn) SetDeadline(t time.Time) error {
	if f := m.SetDeadlineFunc; f != nil {
		return f(t)
	}
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	if f := m.SetWriteDeadlineFunc; f != nil {
		return f(t)
	}
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	if f := m.SetReadDeadlineFunc; f != nil {
		return f(t)
	}
	return nil
}

func (m *MockConn) LocalAddr() net.Addr {
	if f := m.LocalAddrFunc; f != nil {
		return f()
	}
	if m.Local != nil {
		return m.Local
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (m *MockConn) Close() error {
	if f := m.CloseFunc; f != nil {
		return f()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Closed = true
	return nil
}

// MockCreator returns predefined connections in sequence for ListenUDP calls.
type MockCreator struct {
	mu    sync.Mutex
	Conns []net.PacketConn
	Calls []ListenCall
}

type ListenCall struct {
	Network string
	Laddr   *net.UDPAddr
}

func (mc *MockCreator) ListenUDP(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.Calls = append(mc.Calls, ListenCall{Network: network, Laddr: laddr})
	if len(mc.Conns) == 0 {
		// default to a basic mock
		return &MockConn{Local: laddr}, nil
	}
	c := mc.Conns[0]
	mc.Conns = mc.Conns[1:]
	return c, nil
}
