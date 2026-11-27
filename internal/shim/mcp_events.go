// internal/shim/mcp_events.go
package shim

import (
	"net"
	"sync"
)

// MCPEventForwarder sends MCP events to the agentsh server via Unix socket.
type MCPEventForwarder struct {
	conn net.Conn
	mu   sync.Mutex
}

// NewMCPEventForwarder creates a forwarder connected to the event socket.
func NewMCPEventForwarder(socketPath string) (*MCPEventForwarder, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}

	return &MCPEventForwarder{
		conn: conn,
	}, nil
}

// Close closes the event forwarder connection.
func (f *MCPEventForwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.conn != nil {
		return f.conn.Close()
	}
	return nil
}
