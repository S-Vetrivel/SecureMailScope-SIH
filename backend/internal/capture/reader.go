package capture

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketMetadata struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Transport string
	Length    int
	TCPSeq    uint32
	TCPAck    uint32
	TCPFlags  string
	Payload   []byte
	NetFlow   gopacket.Flow
	TCP       *layers.TCP
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

	// Read magic bytes to distinguish pcap from pcapng
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil {
		return 0, fmt.Errorf("failed to read header magic for %s: %w", r.Path, err)
	}

	var packetSource *gopacket.PacketSource
	var linkType layers.LinkType

	type packetReader interface {
		ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	}
	var pktReader packetReader

	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		// PCAPNG format
		ngReader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return 0, fmt.Errorf("failed to create pcapgo ng reader for %s: %w", r.Path, err)
		}
		linkType = ngReader.LinkType()
		pktReader = ngReader
		log.Printf("[READER] %s: PCAPNG, LinkType=%v (%d)", r.Path, linkType, int(linkType))
		packetSource = gopacket.NewPacketSource(ngReader, linkType)
	} else {
		// Standard PCAP format
		rdr, err := pcapgo.NewReader(f)
		if err != nil {
			return 0, fmt.Errorf("failed to create pcapgo reader for %s: %w", r.Path, err)
		}
		linkType = rdr.LinkType()
		pktReader = rdr
		log.Printf("[READER] %s: PCAP, LinkType=%v (%d)", r.Path, linkType, int(linkType))
		packetSource = gopacket.NewPacketSource(rdr, linkType)
	}

	// Allow lazy decoding for performance
	packetSource.DecodeOptions = gopacket.DecodeOptions{
		Lazy:   false,
		NoCopy: true,
	}

	packetCount := 0
	tcpCount := 0

	var getNextPacket func() (gopacket.Packet, error)

	if int(linkType) == 20 {
		// SLL2 linktype (276) is truncated to 20 in gopacket v1.1.19 due to uint8 overflow
		getNextPacket = func() (gopacket.Packet, error) {
			data, ci, err := pktReader.ReadPacketData()
			if err != nil {
				return nil, err
			}
			if len(data) >= 20 {
				// SLL2 Header is 20 bytes. Protocol is first 2 bytes.
				protocolType := uint16(data[0])<<8 | uint16(data[1])
				payload := data[20:]
				var packet gopacket.Packet
				if protocolType == 0x0800 {
					packet = gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
				} else if protocolType == 0x86dd {
					packet = gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default)
				}
				if packet != nil {
					packet.Metadata().Timestamp = ci.Timestamp
					packet.Metadata().Length = ci.Length - 20
					packet.Metadata().CaptureLength = ci.CaptureLength - 20
					return packet, nil
				}
			}
			packet := gopacket.NewPacket(data, linkType, gopacket.Default)
			packet.Metadata().Timestamp = ci.Timestamp
			packet.Metadata().Length = ci.Length
			packet.Metadata().CaptureLength = ci.CaptureLength
			return packet, nil
		}
	} else {
		pktChan := packetSource.Packets()
		getNextPacket = func() (gopacket.Packet, error) {
			packet, ok := <-pktChan
			if !ok {
				return nil, fmt.Errorf("EOF")
			}
			return packet, nil
		}
	}

	for {
		packet, err := getNextPacket()
		if err != nil {
			break
		}
		packetCount++
		meta := PacketMetadata{
			Timestamp: packet.Metadata().Timestamp,
			Length:    packet.Metadata().Length,
		}

		// Network layer — try IPv4 then IPv6
		var gotIP bool
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4, _ := ip4Layer.(*layers.IPv4)
			meta.SrcIP = ip4.SrcIP.String()
			meta.DstIP = ip4.DstIP.String()
			meta.NetFlow = ip4.NetworkFlow()
			gotIP = true
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6, _ := ip6Layer.(*layers.IPv6)
			meta.SrcIP = ip6.SrcIP.String()
			meta.DstIP = ip6.DstIP.String()
			meta.NetFlow = ip6.NetworkFlow()
			gotIP = true
		}

		if !gotIP {
			// Log the first few unknown packets to help diagnose LinkType issues
			if packetCount <= 3 {
				var layerNames []string
				for _, l := range packet.Layers() {
					layerNames = append(layerNames, l.LayerType().String())
				}
				log.Printf("[READER] pkt#%d: no IP layer found, layers=%v, data[0:4]=%x",
					packetCount, layerNames, packet.Data()[:min(4, len(packet.Data()))])
			}
			continue
		}

		// Transport layer — TCP only
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			meta.SrcPort = uint16(tcp.SrcPort)
			meta.DstPort = uint16(tcp.DstPort)
			meta.Transport = "TCP"
			meta.TCPSeq = tcp.Seq
			meta.TCPAck = tcp.Ack
			meta.Payload = tcp.Payload
			meta.TCPFlags = formatTCPFlags(tcp)
			meta.TCP = tcp
			tcpCount++
		} else {
			continue
		}

		if err := onPacket(meta); err != nil {
			return packetCount, err
		}
	}

	log.Printf("[READER] %s: read %d total packets, %d TCP", r.Path, packetCount, tcpCount)
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
