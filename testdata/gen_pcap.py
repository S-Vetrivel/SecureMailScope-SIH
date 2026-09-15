import struct
import time

def create_pcap(filename):
    with open(filename, 'wb') as f:
        # PCAP Global Header: magic 0xa1b2c3d4, v2.4, tz 0, sig 0, snaplen 65535, network 1 (Ethernet)
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        # Helper to construct Ethernet + IPv4 + TCP packet
        def make_pkt(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b''):
            # Ethernet header (14 bytes)
            eth = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00'
            
            # IPv4 header (20 bytes)
            ip_len = 20 + 20 + len(payload)
            src_bytes = bytes(map(int, src_ip.split('.')))
            dst_bytes = bytes(map(int, dst_ip.split('.')))
            ip = struct.pack('!BBHHHBBH4s4s',
                0x45, 0x00, ip_len, 0x1234, 0x4000, 64, 6, 0, src_bytes, dst_bytes
            )
            
            # TCP header (20 bytes)
            tcp = struct.pack('!HHIIBBHHH',
                src_port, dst_port, seq, ack, (5 << 4), flags, 64240, 0, 0
            )
            
            packet_data = eth + ip + tcp + payload
            now = int(time.time())
            pkt_hdr = struct.pack('<IIII', now, 0, len(packet_data), len(packet_data))
            return pkt_hdr + packet_data

        packets = []

        # 1. SMTPS Session 1 (Port 465 - TLS 1.3 with Forward Secrecy)
        packets.append(make_pkt('192.168.1.50', '198.51.100.25', 54321, 465, 1000, 0, 0x02)) # SYN
        packets.append(make_pkt('198.51.100.25', '192.168.1.50', 465, 54321, 2000, 1001, 0x12)) # SYN-ACK
        packets.append(make_pkt('192.168.1.50', '198.51.100.25', 54321, 465, 1001, 2001, 0x10)) # ACK
        
        # TLS ClientHello (TLS 1.3 ClientHello with SNI example.com and SupportedVersions=TLS 1.3)
        client_hello_payload = bytes.fromhex(
            "16030100c8010000c403030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000020013010001000099"
            "00000010000e00000b6578616d706c652e636f6d" # SNI example.com
            "002b0003020304" # Supported versions TLS 1.3 (0x0304)
            "001300040002001d" # Supported group x25519 (0x001d)
        )
        packets.append(make_pkt('192.168.1.50', '198.51.100.25', 54321, 465, 1001, 2001, 0x18, client_hello_payload))
        
        # TLS ServerHello (Negotiates TLS 1.3 + TLS_AES_128_GCM_SHA256)
        server_hello_payload = bytes.fromhex(
            "160303005a020000560303a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00130100002e"
            "002b00020304" # Negotiated version TLS 1.3
            "00330024001d00200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        )
        packets.append(make_pkt('198.51.100.25', '192.168.1.50', 465, 54321, 2001, 1201, 0x18, server_hello_payload))

        # 2. STARTTLS Session 2 (Port 25 - Plaintext banner -> STARTTLS upgrade)
        packets.append(make_pkt('192.168.1.55', '198.51.100.26', 54322, 25, 3000, 0, 0x02))
        packets.append(make_pkt('198.51.100.26', '192.168.1.55', 25, 54322, 4000, 3001, 0x12))
        packets.append(make_pkt('198.51.100.26', '192.168.1.55', 25, 54322, 4001, 3001, 0x18, b"220 mail.secure.org ESMTP\r\n"))
        packets.append(make_pkt('192.168.1.55', '198.51.100.26', 54322, 25, 3001, 4028, 0x18, b"EHLO client.org\r\n"))
        packets.append(make_pkt('198.51.100.26', '192.168.1.55', 25, 54322, 4028, 3018, 0x18, b"250-mail.secure.org\r\n250 STARTTLS\r\n"))
        packets.append(make_pkt('192.168.1.55', '198.51.100.26', 54322, 25, 3018, 4064, 0x18, b"STARTTLS\r\n"))
        packets.append(make_pkt('198.51.100.26', '192.168.1.55', 25, 54322, 4064, 3028, 0x18, b"220 2.0.0 Ready to start TLS\r\n"))

        # 3. IMAPS Session 3 (Port 993 - TLS 1.0 Deprecated Protocol)
        packets.append(make_pkt('192.168.1.60', '198.51.100.27', 54323, 993, 5000, 0, 0x02))
        packets.append(make_pkt('198.51.100.27', '192.168.1.60', 993, 54323, 6000, 5001, 0x12))
        
        # TLS 1.0 ServerHello with TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)
        imaps_server_hello = bytes.fromhex(
            "160301004a020000460301a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00002f00"
        )
        packets.append(make_pkt('198.51.100.27', '192.168.1.60', 993, 54323, 6001, 5001, 0x18, imaps_server_hello))

        # Write all packets to file
        for p in packets:
            f.write(p)

    print(f"Generated synthetic PCAP file: {filename}")

if __name__ == '__main__':
    create_pcap('testdata/sample_traffic.pcap')
