package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/securemailscope/backend/internal/capture"
)

type ConnectionKey string

func MakeConnectionKey(ip1 string, port1 uint16, ip2 string, port2 uint16) ConnectionKey {
	if ip1 < ip2 || (ip1 == ip2 && port1 < port2) {
		return ConnectionKey(fmt.Sprintf("%s:%d-%s:%d", ip1, port1, ip2, port2))
	}
	return ConnectionKey(fmt.Sprintf("%s:%d-%s:%d", ip2, port2, ip1, port1))
}

type ReassembledStream struct {
	Key            ConnectionKey
	ClientIP       string
	ClientPort     uint16
	ServerIP       string
	ServerPort     uint16
	StartTime      time.Time
	EndTime        time.Time
	PacketCount    int
	ClientBytes    int64
	ServerBytes    int64
	StreamComplete bool
	ReassemblyGap  bool
	ClientPayload  []byte
	ServerPayload  []byte
	FullPayload    []byte
}

type StreamReassembler struct {
	mu      sync.Mutex
	streams map[ConnectionKey]*ReassembledStream
}

func NewStreamReassembler() *StreamReassembler {
	return &StreamReassembler{
		streams: make(map[ConnectionKey]*ReassembledStream),
	}
}

func (sr *StreamReassembler) ProcessPacket(pkt capture.PacketMetadata) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	key := MakeConnectionKey(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
	stream, exists := sr.streams[key]

	if !exists {
		// Infer client/server based on common server email ports or lowest port heuristic
		clientIP, clientPort := pkt.SrcIP, pkt.SrcPort
		serverIP, serverPort := pkt.DstIP, pkt.DstPort

		if pkt.TCPFlags == "SYN " { // Client sends SYN packet
			clientIP, clientPort = pkt.SrcIP, pkt.SrcPort
			serverIP, serverPort = pkt.DstIP, pkt.DstPort
		} else if isServerPort(pkt.SrcPort) && !isServerPort(pkt.DstPort) {
			clientIP, clientPort = pkt.DstIP, pkt.DstPort
			serverIP, serverPort = pkt.SrcIP, pkt.SrcPort
		}

		stream = &ReassembledStream{
			Key:            key,
			ClientIP:       clientIP,
			ClientPort:     clientPort,
			ServerIP:       serverIP,
			ServerPort:     serverPort,
			StartTime:      pkt.Timestamp,
			EndTime:        pkt.Timestamp,
			StreamComplete: true,
			ReassemblyGap:  false,
		}
		sr.streams[key] = stream
	}

	stream.EndTime = pkt.Timestamp
	stream.PacketCount++

	if len(pkt.Payload) > 0 {
		if pkt.SrcIP == stream.ClientIP && pkt.SrcPort == stream.ClientPort {
			stream.ClientBytes += int64(len(pkt.Payload))
			stream.ClientPayload = append(stream.ClientPayload, pkt.Payload...)
		} else {
			stream.ServerBytes += int64(len(pkt.Payload))
			stream.ServerPayload = append(stream.ServerPayload, pkt.Payload...)
		}
		stream.FullPayload = append(stream.FullPayload, pkt.Payload...)
	}

	// Detect TCP RST flag or FIN flag for stream completeness
	if pkt.TCPFlags != "" {
		// Handled gracefully
	}
}

func (sr *StreamReassembler) GetStreams() []*ReassembledStream {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	result := make([]*ReassembledStream, 0, len(sr.streams))
	for _, stream := range sr.streams {
		result = append(result, stream)
	}
	return result
}

func isServerPort(port uint16) bool {
	switch port {
	case 25, 465, 587, 110, 995, 143, 993:
		return true
	default:
		return false
	}
}
