package capture

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketMetadata struct {
	Timestamp      time.Time
	SrcIP          string
	DstIP          string
	SrcPort        uint16
	DstPort        uint16
	Transport      string
	Length         int
	TCPSeq         uint32
	TCPAck         uint32
	TCPFlags       string
	Payload        []byte
	Layer3Layer    gopacket.Layer
	Layer4Layer    gopacket.Layer
}

type PCAPReader struct {
	Path string
}

func NewPCAPReader(path string) *PCAPReader {
	return &PCAPReader{Path: path}
}

func (r *PCAPReader) ReadPackets(onPacket func(pkt PacketMetadata) error) (int, error) {
	f, err := os.Open(r.Path)
	if err != nil {
		return 0, fmt.Errorf("failed to open pcap file %s: %w", r.Path, err)
	}
	defer f.Close()

	// Check magic bytes to select pcap vs pcapng reader
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil {
		return 0, fmt.Errorf("failed to read header magic for %s: %w", r.Path, err)
	}

	var packetSource *gopacket.PacketSource
	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		// PCAPNG format
		ngReader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return 0, fmt.Errorf("failed to create pcapgo ng reader for %s: %w", r.Path, err)
		}
		packetSource = gopacket.NewPacketSource(ngReader, ngReader.LinkType())
	} else {
		// Standard PCAP format
		rdr, err := pcapgo.NewReader(f)
		if err != nil {
			return 0, fmt.Errorf("failed to create pcapgo reader for %s: %w", r.Path, err)
		}
		packetSource = gopacket.NewPacketSource(rdr, rdr.LinkType())
	}

	packetCount := 0

	for packet := range packetSource.Packets() {
		packetCount++
		meta := PacketMetadata{
			Timestamp: packet.Metadata().Timestamp,
			Length:    packet.Metadata().Length,
		}

		// Network layer (IPv4 or IPv6)
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4, _ := ip4Layer.(*layers.IPv4)
			meta.SrcIP = ip4.SrcIP.String()
			meta.DstIP = ip4.DstIP.String()
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6, _ := ip6Layer.(*layers.IPv6)
			meta.SrcIP = ip6.SrcIP.String()
			meta.DstIP = ip6.DstIP.String()
		} else {
			// Skip non-IP packets safely
			continue
		}

		// Transport layer (TCP)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			meta.SrcPort = uint16(tcp.SrcPort)
			meta.DstPort = uint16(tcp.DstPort)
			meta.Transport = "TCP"
			meta.TCPSeq = tcp.Seq
			meta.TCPAck = tcp.Ack
			meta.Payload = tcp.Payload
			meta.TCPFlags = formatTCPFlags(tcp)
		} else {
			// Ignore non-TCP safely
			continue
		}

		if err := onPacket(meta); err != nil {
			return packetCount, err
		}
	}

	return packetCount, nil
}

func formatTCPFlags(tcp *layers.TCP) string {
	var flags string
	if tcp.SYN {
		flags += "SYN "
	}
	if tcp.ACK {
		flags += "ACK "
	}
	if tcp.FIN {
		flags += "FIN "
	}
	if tcp.RST {
		flags += "RST "
	}
	if tcp.PSH {
		flags += "PSH "
	}
	if tcp.URG {
		flags += "URG "
	}
	return flags
}
