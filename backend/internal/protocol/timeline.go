package protocol

import (
	"bytes"
	"strings"

	"github.com/securemailscope/backend/internal/models"
	"github.com/securemailscope/backend/internal/session"
)

type TimelineAnalyzer struct{}

func NewTimelineAnalyzer() *TimelineAnalyzer {
	return &TimelineAnalyzer{}
}

func (a *TimelineAnalyzer) Analyze(proto models.EmailProtocol, stream *session.ReassembledStream) ([]models.ProtocolEvent, models.StartTLSInfo) {
	var events []models.ProtocolEvent
	startTLS := models.StartTLSInfo{
		State:          models.StatePlaintext,
		Supported:      false,
		Requested:      false,
		Accepted:       false,
		TLSStarted:     false,
		TLSEstablished: false,
	}

	// We will combine chunks line by line to extract commands.
	var clientBuf, serverBuf []byte
	var lastClientCmd string

	processClientLine := func(line string, ts int64) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		
		upper := strings.ToUpper(line)
		
		// For IMAP, strip the tag
		cmdWord := upper
		if proto == models.ProtocolIMAP {
			parts := strings.SplitN(upper, " ", 2)
			if len(parts) == 2 {
				cmdWord = parts[1]
			}
		} else if proto == models.ProtocolPOP3 || proto == models.ProtocolSMTP {
			parts := strings.SplitN(upper, " ", 2)
			cmdWord = parts[0]
		}
		
		// Only track meaningful commands to avoid harvesting content
		isMeaningful := false
		switch proto {
		case models.ProtocolSMTP:
			if cmdWord == "EHLO" || cmdWord == "HELO" || cmdWord == "STARTTLS" || cmdWord == "AUTH" || cmdWord == "MAIL" || cmdWord == "RCPT" || cmdWord == "DATA" || cmdWord == "QUIT" {
				isMeaningful = true
			}
		case models.ProtocolIMAP:
			if strings.HasPrefix(cmdWord, "CAPABILITY") || strings.HasPrefix(cmdWord, "STARTTLS") || strings.HasPrefix(cmdWord, "LOGIN") || strings.HasPrefix(cmdWord, "AUTHENTICATE") || strings.HasPrefix(cmdWord, "SELECT") || strings.HasPrefix(cmdWord, "FETCH") || strings.HasPrefix(cmdWord, "LOGOUT") {
				isMeaningful = true
			}
		case models.ProtocolPOP3:
			if cmdWord == "STLS" || cmdWord == "USER" || cmdWord == "PASS" || cmdWord == "LIST" || cmdWord == "RETR" || cmdWord == "QUIT" {
				isMeaningful = true
			}
		}

		if isMeaningful {
			// Don't log full AUTH/LOGIN credentials
			cleanCmd := line
			if strings.HasPrefix(upper, "AUTH") || strings.Contains(upper, "LOGIN ") || strings.HasPrefix(upper, "PASS ") {
				cleanCmd = cmdWord + " <redacted>"
			}

			events = append(events, models.ProtocolEvent{
				Timestamp: stream.StartTime, // Close enough, we use stream.StartTime as base, will fix if possible
				Direction: "client_to_server",
				Command:   cleanCmd,
			})
			lastClientCmd = upper
		}

		// STARTTLS tracking
		if (proto == models.ProtocolSMTP && cmdWord == "STARTTLS") || 
		   (proto == models.ProtocolIMAP && strings.HasPrefix(cmdWord, "STARTTLS")) ||
		   (proto == models.ProtocolPOP3 && cmdWord == "STLS") {
			startTLS.Requested = true
			startTLS.State = models.StateCommandSent
		}
	}

	processServerLine := func(line string, ts int64) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		upper := strings.ToUpper(line)
		
		if lastClientCmd != "" && len(events) > 0 {
			events[len(events)-1].Response = line
			lastClientCmd = ""
		} else {
			// Server greeting or unsolicited response
			isMeaningful := false
			if proto == models.ProtocolSMTP && (strings.HasPrefix(upper, "220") || strings.HasPrefix(upper, "250")) {
				isMeaningful = true
			} else if proto == models.ProtocolIMAP && (strings.HasPrefix(upper, "* OK") || strings.HasPrefix(upper, "* CAPABILITY")) {
				isMeaningful = true
			} else if proto == models.ProtocolPOP3 && strings.HasPrefix(upper, "+OK") {
				isMeaningful = true
			}
			
			if isMeaningful {
				events = append(events, models.ProtocolEvent{
					Timestamp: stream.StartTime,
					Direction: "server_to_client",
					Response:  line,
				})
			}
		}

		// STARTTLS support advertized?
		if (proto == models.ProtocolSMTP && strings.Contains(upper, "STARTTLS")) ||
		   (proto == models.ProtocolIMAP && strings.Contains(upper, "STARTTLS")) ||
		   (proto == models.ProtocolPOP3 && strings.Contains(upper, "STLS")) {
			startTLS.Supported = true
		}

		// STARTTLS accepted?
		if startTLS.Requested && !startTLS.Accepted {
			if (proto == models.ProtocolSMTP && strings.HasPrefix(upper, "220")) ||
			   (proto == models.ProtocolIMAP && strings.Contains(upper, "OK")) ||
			   (proto == models.ProtocolPOP3 && strings.HasPrefix(upper, "+OK")) {
				startTLS.Accepted = true
				startTLS.State = models.StateAccepted
				startTLS.TLSStarted = true
			} else {
				startTLS.State = models.StateFailed
			}
		}
	}

	for _, chunk := range stream.Chunks {
		if chunk.IsClient {
			clientBuf = append(clientBuf, chunk.Data...)
			for {
				idx := bytes.IndexByte(clientBuf, '\n')
				if idx == -1 {
					break
				}
				line := string(clientBuf[:idx])
				clientBuf = clientBuf[idx+1:]
				
				// Apply timestamp from chunk
				events_len := len(events)
				processClientLine(line, 0)
				if len(events) > events_len {
					events[len(events)-1].Timestamp = chunk.Timestamp
				}
				
				// Stop parsing plaintext if TLS has started (avoid garbage binary parsing)
				if startTLS.Accepted {
					break
				}
			}
		} else {
			serverBuf = append(serverBuf, chunk.Data...)
			for {
				idx := bytes.IndexByte(serverBuf, '\n')
				if idx == -1 {
					break
				}
				line := string(serverBuf[:idx])
				serverBuf = serverBuf[idx+1:]
				
				events_len := len(events)
				processServerLine(line, 0)
				if len(events) > events_len {
					events[len(events)-1].Timestamp = chunk.Timestamp
				}

				if startTLS.Accepted {
					break
				}
			}
		}
		if startTLS.Accepted && bytesContainTLSClientHello(chunk.Data) {
			startTLS.State = models.StateEncrypted
			startTLS.TLSEstablished = true
		}
	}
	
	if !startTLS.Supported && !startTLS.Requested {
		startTLS.State = models.StateStartTLSNotUsed
	}

	return events, startTLS
}

func bytesContainTLSClientHello(payload []byte) bool {
	for i := 0; i < len(payload)-5; i++ {
		if payload[i] == 0x16 && payload[i+1] == 0x03 && (payload[i+2] >= 0x00 && payload[i+2] <= 0x04) {
			if payload[i+5] == 0x01 { // Handshake type: ClientHello
				return true
			}
		}
	}
	return false
}
