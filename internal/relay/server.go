package relay

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	// Allow all origins — the relay URL is semi-secret (only in Workers KV)
	// and WireGuard provides E2E encryption regardless.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Server is a WebSocket relay server that bridges WireGuard UDP packets
// from the local WireGuard device to a remote relay client (the Mac).
// It runs on the PC, exposed externally via cloudflared.
type Server struct {
	wgListenPort int
	httpServer   *http.Server
}

// NewServer creates a relay Server.
// wgListenPort is the port WireGuard is listening on locally (typically 51820).
func NewServer(wgListenPort int) *Server {
	s := &Server{wgListenPort: wgListenPort}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", RelayHTTPPort),
		Handler: mux,
	}
	return s
}

// Start begins serving in a background goroutine.
func (s *Server) Start() {
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("relay server: %v", err)
		}
	}()
	log.Printf("relay: server listening on 127.0.0.1:%d", RelayHTTPPort)
}

// Stop shuts down the HTTP server.
func (s *Server) Stop() {
	s.httpServer.Close()
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("relay: WS upgrade: %v", err)
		return
	}
	defer ws.Close()
	log.Printf("relay: client connected from %s", r.RemoteAddr)

	// Bind a local UDP socket on RelayUDPPort.
	// WireGuard is configured to send to this port as the peer's endpoint.
	// Responses from WireGuard also arrive here.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: RelayUDPPort,
	})
	if err != nil {
		log.Printf("relay: bind UDP: %v", err)
		return
	}
	defer udpConn.Close()

	wgAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: s.wgListenPort,
	}

	log.Printf("relay: bridging UDP 127.0.0.1:%d ↔ WebSocket", RelayUDPPort)
	bridge(udpConn, wgAddr, ws)
	log.Printf("relay: client disconnected")
}
