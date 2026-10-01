package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/securemailscope/backend/internal/capture"
)

type ConnectionKey string

func MakeConnectionKey(ip1 string, port1 uint16, ip2 string, port2 uint16) ConnectionKey {
	if ip1 < ip2 || (ip1 == ip2 && port1 < port2) {
		return ConnectionKey(fmt.Sprintf("%s:%d-%s:%d", ip1, port1, ip2, port2))
	}
	return ConnectionKey(fmt.Sprintf("%s:%d-%s:%d", ip2, port2, ip1, port1))
}

type PayloadChunk struct {
	Timestamp time.Time
	IsClient  bool
	Data      []byte
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
	Retransmissions int
	Chunks         []PayloadChunk
}

type StreamReassembler struct {
	mu             sync.Mutex
	streams        map[ConnectionKey]*ReassembledStream
	assembler      *tcpassembly.Assembler
	streamFactory  *streamFactory
}

// streamFactory implements tcpassembly.StreamFactory
type streamFactory struct {
	sr *StreamReassembler
}

// bidiStream implements tcpassembly.Stream
type bidiStream struct {
	net, transport gopacket.Flow
	sr             *StreamReassembler
	isClient       bool
	key            ConnectionKey
}

func (f *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	s := &bidiStream{
		net:       net,
		transport: transport,
		sr:        f.sr,
	}

	srcIP, dstIP := net.Endpoints()
	srcPort, dstPort := transport.Endpoints()
	sSrcIP := srcIP.String()
	sDstIP := dstIP.String()
	srcPortStr := srcPort.String()
	dstPortStr := dstPort.String()
	var iSrcPort, iDstPort uint16
	fmt.Sscanf(srcPortStr, "%d", &iSrcPort)
	fmt.Sscanf(dstPortStr, "%d", &iDstPort)

	key := MakeConnectionKey(sSrcIP, iSrcPort, sDstIP, iDstPort)
	s.key = key

	f.sr.mu.Lock()
	stream, exists := f.sr.streams[key]
	if !exists {
		clientIP, clientPort := sSrcIP, iSrcPort
		serverIP, serverPort := sDstIP, iDstPort

		if isServerPort(iSrcPort) && !isServerPort(iDstPort) {
			clientIP, clientPort = sDstIP, iDstPort
			serverIP, serverPort = sSrcIP, iSrcPort
		}

		stream = &ReassembledStream{
			Key:        key,
			ClientIP:   clientIP,
			ClientPort: clientPort,
			ServerIP:   serverIP,
			ServerPort: serverPort,
		}
		f.sr.streams[key] = stream
	}
	f.sr.mu.Unlock()

	s.isClient = (sSrcIP == stream.ClientIP && iSrcPort == stream.ClientPort)
	return s
}

func (s *bidiStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	s.sr.mu.Lock()
	defer s.sr.mu.Unlock()
	stream := s.sr.streams[s.key]

	for _, reassembly := range reassemblies {
		if reassembly.Skip > 0 {
			stream.ReassemblyGap = true
		}
		if len(reassembly.Bytes) > 0 {
			n := len(reassembly.Bytes)
			if s.isClient {
				stream.ClientBytes += int64(n)
				stream.ClientPayload = append(stream.ClientPayload, reassembly.Bytes...)
			} else {
				stream.ServerBytes += int64(n)
				stream.ServerPayload = append(stream.ServerPayload, reassembly.Bytes...)
			}
			stream.FullPayload = append(stream.FullPayload, reassembly.Bytes...)
			
			// Copy data so it's not overwritten
			dataCopy := make([]byte, n)
			copy(dataCopy, reassembly.Bytes)
			stream.Chunks = append(stream.Chunks, PayloadChunk{
				Timestamp: reassembly.Seen,
				IsClient:  s.isClient,
				Data:      dataCopy,
			})
		}
	}
}

func (s *bidiStream) ReassemblyComplete() {
	s.sr.mu.Lock()
	defer s.sr.mu.Unlock()
	stream := s.sr.streams[s.key]
	stream.StreamComplete = true
}

func NewStreamReassembler() *StreamReassembler {
	sr := &StreamReassembler{
		streams: make(map[ConnectionKey]*ReassembledStream),
	}
	sr.streamFactory = &streamFactory{sr: sr}
	pool := tcpassembly.NewStreamPool(sr.streamFactory)
	sr.assembler = tcpassembly.NewAssembler(pool)
	return sr
}

func (sr *StreamReassembler) ProcessPacket(pkt capture.PacketMetadata) {
	sr.mu.Lock()
	key := MakeConnectionKey(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
	stream, exists := sr.streams[key]
	if !exists {
		clientIP, clientPort := pkt.SrcIP, pkt.SrcPort
		serverIP, serverPort := pkt.DstIP, pkt.DstPort

		if pkt.TCPFlags == "SYN " {
			clientIP, clientPort = pkt.SrcIP, pkt.SrcPort
			serverIP, serverPort = pkt.DstIP, pkt.DstPort
		} else if isServerPort(pkt.SrcPort) && !isServerPort(pkt.DstPort) {
			clientIP, clientPort = pkt.DstIP, pkt.DstPort
			serverIP, serverPort = pkt.SrcIP, pkt.SrcPort
		}

		stream = &ReassembledStream{
			Key:        key,
			ClientIP:   clientIP,
			ClientPort: clientPort,
			ServerIP:   serverIP,
			ServerPort: serverPort,
			StartTime:  pkt.Timestamp,
			EndTime:    pkt.Timestamp,
		}
		sr.streams[key] = stream
	}
	if stream.StartTime.IsZero() || pkt.Timestamp.Before(stream.StartTime) {
		stream.StartTime = pkt.Timestamp
	}
	if pkt.Timestamp.After(stream.EndTime) {
		stream.EndTime = pkt.Timestamp
	}
	stream.PacketCount++
	sr.mu.Unlock()

	// Feed to tcpassembly
	if pkt.TCP != nil {
		sr.assembler.AssembleWithTimestamp(pkt.NetFlow, pkt.TCP, pkt.Timestamp)
	}
}

func (sr *StreamReassembler) GetStreams() []*ReassembledStream {
	// Flush assembler
	sr.assembler.FlushAll()

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
