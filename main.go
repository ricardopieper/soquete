package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

type HttpPacket struct {
	Code            int
	CodeDescription string
	Headers         map[string]string
	Body            string
}

func parseHttpPacket(packet string) (HttpPacket, error) {

	lines := strings.Split(packet, "\r\n")
	if len(lines) < 1 {
		return HttpPacket{}, fmt.Errorf("invalid HTTP packet")
	}

	requestLine := lines[0]
	parts := strings.Split(requestLine, " ")
	if len(parts) < 3 {
		return HttpPacket{}, fmt.Errorf("invalid HTTP request line")
	}
	code := parts[1]
	codeDescription := parts[2]
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		splitted := strings.Split(line, ":")
		trimmedKey := strings.TrimSpace(splitted[0])
		trimmedVal := strings.TrimSpace(strings.Join(splitted[1:], ":"))
		headers[trimmedKey] = trimmedVal

	}
	codeAsInt, err := strconv.Atoi(code)
	if err != nil {
		return HttpPacket{}, fmt.Errorf("invalid string for code: %s", code)
	}
	return HttpPacket{
		Code:            codeAsInt,
		CodeDescription: codeDescription,
		Headers:         headers,
	}, nil
}

func websocketValidate(key string, packet HttpPacket) {
	if packet.Headers == nil {
		panic("Headers nil, expected non-empty")
	}

	if accept, ok := packet.Headers["Sec-Websocket-Accept"]; ok {
		str := key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		hasher := sha1.New()
		hasher.Write([]byte(str))
		result := hasher.Sum(nil)
		expectedAccept := base64.StdEncoding.EncodeToString(result)

		fmt.Printf("Sec-Websocket-Accept: Expected: %s, got: %s\n", expectedAccept, accept)
		if accept != expectedAccept {
			panic("Expected same websocket accept")
		} else {
			println("Same websocket accept, continuing with upgrade")
		}
	}
}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
*/

type Opcode byte

const (
	Continuation Opcode = iota
	Text
	Binary
	Reserved3
	Reserved4
	Reserved5
	Reserved6
	Reserved7
	ConnectionClose
	Ping
	Pong
	ReservedB
	ReservedC
	ReservedD
	ReservedE
	ReservedF
)

type FrameType byte

const (
	TextFrame FrameType = iota
	BinaryFrame
)

type WebsocketMessage struct {
	Type    FrameType
	Payload []byte
}

type WebsocketFrame struct {
	Fin         bool
	Rsv         byte
	Opcode      Opcode
	Payload     []byte
	PayloadSize uint64
	ClosingCode int
}

func readWebsocketFrame(reader io.Reader) (WebsocketFrame, error) {
	var frameHeader [2]byte
	//conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadFull(reader, frameHeader[:])

	if err != nil {
		return WebsocketFrame{}, err
	}

	flagsAndOpcode := frameHeader[0]
	maskAndPayloadSize := frameHeader[1]

	fin := (flagsAndOpcode & 0b10000000) != 0
	rsv := (flagsAndOpcode & 0b01110000) >> 4

	opcode := Opcode(flagsAndOpcode & 0b00001111)
	mask := maskAndPayloadSize >> 7

	if mask != 0 {
		panic("Mask is 1, should be 0 coming from server")
	}
	//kills
	payloadSize := uint64(maskAndPayloadSize & 0b01111111)
	if opcode == ConnectionClose {
		if payloadSize == 0 {
			return WebsocketFrame{
				Fin:         fin,
				Rsv:         rsv,
				Opcode:      ConnectionClose,
				PayloadSize: 0,
				Payload:     []byte{},
				ClosingCode: int(0),
			}, nil
		}

		var codeBuf []byte = make([]byte, payloadSize)
		io.ReadFull(reader, codeBuf)
		var code uint16 = 0
		if payloadSize > 1 {
			code = binary.BigEndian.Uint16(codeBuf[:])
		}
		fmt.Printf("Close code: %d\n", code)
		return WebsocketFrame{
			Fin:         fin,
			Rsv:         rsv,
			Opcode:      ConnectionClose,
			PayloadSize: payloadSize,
			Payload:     codeBuf[:],
			ClosingCode: int(code),
		}, nil
	}

	if payloadSize == 126 {
		var sizeBytes [2]byte
		if _, err := io.ReadFull(reader, sizeBytes[:]); err != nil {
			return WebsocketFrame{}, err
		}
		payloadSize = uint64(binary.BigEndian.Uint16(sizeBytes[:]))
	} else if payloadSize == 127 {
		var sizeBytes [8]byte
		if _, err := io.ReadFull(reader, sizeBytes[:]); err != nil {
			return WebsocketFrame{}, err
		}
		payloadSize = binary.BigEndian.Uint64(sizeBytes[:])
	}
	fmt.Printf("Payload size: %v\n", payloadSize)
	payloadBytes := make([]byte, payloadSize)
	io.ReadFull(reader, payloadBytes)

	return WebsocketFrame{
		Fin:         fin,
		PayloadSize: payloadSize,
		Rsv:         rsv,
		Opcode:      opcode,
		Payload:     payloadBytes,
	}, nil

}

func isReservedOpcode(opcode Opcode) bool {
	return opcode == Reserved3 ||
		opcode == Reserved4 ||
		opcode == Reserved5 ||
		opcode == Reserved6 ||
		opcode == Reserved7 ||
		opcode == ReservedB ||
		opcode == ReservedC ||
		opcode == ReservedD ||
		opcode == ReservedE ||
		opcode == ReservedF
}

func isControlMessage(opcode Opcode) bool {
	return opcode == Ping ||
		opcode == Pong ||
		opcode == ConnectionClose
}

func couldBeUtf8(utf8ValBuf *[]byte, payload []byte) bool {
	*utf8ValBuf = append(*utf8ValBuf, payload...)
	for utf8.FullRune(*utf8ValBuf) {
		r, size := utf8.DecodeRune(*utf8ValBuf)
		if r == utf8.RuneError && size == 1 {
			return false
		}
		*utf8ValBuf = (*utf8ValBuf)[size:]
	}
	return true
}

func runLoop(reader io.Reader, conn net.Conn, closeSignal chan int) {
	expectingFragment := false
	isTextStream := false
	utf8ValBuf := make([]byte, 0)
	var currentMessage []WebsocketFrame = make([]WebsocketFrame, 0)
	for {
		frame, err := readWebsocketFrame(reader)
		if err != nil {
			break
		}

		if isControlMessage(frame.Opcode) && frame.PayloadSize > 125 {
			sendFrame(conn, WebsocketFrame{
				Fin:         true,
				Opcode:      ConnectionClose,
				Payload:     frame.Payload,
				ClosingCode: 1002,
			})
			break
		}

		if isControlMessage(frame.Opcode) && !frame.Fin {
			sendFrame(conn, WebsocketFrame{
				Fin:         true,
				Opcode:      ConnectionClose,
				Payload:     frame.Payload,
				ClosingCode: 1002,
			})
			break
		}

		if frame.Opcode == Ping {
			println("got ping")
			println("Payload: " + string(frame.Payload))
			sendFrame(conn, WebsocketFrame{
				Fin:     true,
				Opcode:  Pong,
				Payload: frame.Payload,
			})
		} else if frame.Opcode == Pong {
			//ignore
		} else if frame.Rsv != 0 || isReservedOpcode(frame.Opcode) {

			fmt.Printf("Opcode used: %v", frame.Opcode)
			sendFrame(conn, WebsocketFrame{
				Fin:         true,
				Opcode:      ConnectionClose,
				Payload:     []byte{},
				ClosingCode: 1002,
				Rsv:         0,
			})
			break
		} else if frame.Opcode == ConnectionClose {
			if frame.PayloadSize == 0 {
				sendFrame(conn, WebsocketFrame{
					Fin:         true,
					Opcode:      ConnectionClose,
					Payload:     []byte{},
					PayloadSize: 0,
					ClosingCode: 1000,
					Rsv:         0,
				})
				break
			}
			if frame.PayloadSize == 1 {
				sendFrame(conn, WebsocketFrame{
					Fin:         true,
					Opcode:      ConnectionClose,
					Payload:     []byte{},
					PayloadSize: 0,
					ClosingCode: 1002,
					Rsv:         0,
				})
				break
			}

			if len(frame.Payload) > 2 && !utf8.Valid(frame.Payload[2:]) {
				sendFrame(conn, WebsocketFrame{
					Fin:         true,
					Opcode:      ConnectionClose,
					Payload:     []byte{},
					ClosingCode: 1007,
					Rsv:         0,
				})
				break
			}

			if (frame.ClosingCode < 1000 || frame.ClosingCode > 1015 || frame.ClosingCode == 1004 || frame.ClosingCode == 1005 || frame.ClosingCode == 1006) &&
				(frame.ClosingCode < 3000 || frame.ClosingCode > 4999) {
				sendFrame(conn, WebsocketFrame{
					Fin:         true,
					Opcode:      ConnectionClose,
					Payload:     []byte{},
					ClosingCode: 1002,
					Rsv:         0,
				})
				break
			}

			sendFrame(conn, WebsocketFrame{
				Fin:         true,
				Opcode:      ConnectionClose,
				Payload:     []byte{},
				ClosingCode: 1000,
				Rsv:         0,
			})
			break
		} else {
			if !frame.Fin && frame.Opcode != Continuation && !expectingFragment {
				//reading first fragment, expects more
				expectingFragment = true
				isTextStream = frame.Opcode == Text
				currentMessage = append(currentMessage, frame)
				if isTextStream {
					if !couldBeUtf8(&utf8ValBuf, frame.Payload) {
						sendFrame(conn, WebsocketFrame{
							Fin:         true,
							Opcode:      ConnectionClose,
							Payload:     []byte{},
							ClosingCode: 1007,
						})
						break
					}
				}
			} else if !frame.Fin && expectingFragment && frame.Opcode == Continuation {
				//mid continuation
				expectingFragment = true
				currentMessage = append(currentMessage, frame)
				if isTextStream {
					if !couldBeUtf8(&utf8ValBuf, frame.Payload) {
						sendFrame(conn, WebsocketFrame{
							Fin:         true,
							Opcode:      ConnectionClose,
							Payload:     []byte{},
							ClosingCode: 1007,
						})
						break
					}
				}

			} else if frame.Fin && expectingFragment && frame.Opcode == Continuation {
				//end of fragmented message
				expectingFragment = false

				currentMessage = append(currentMessage, frame)

				if isTextStream {
					if !couldBeUtf8(&utf8ValBuf, frame.Payload) {
						sendFrame(conn, WebsocketFrame{
							Fin:         true,
							Opcode:      ConnectionClose,
							Payload:     []byte{},
							ClosingCode: 1007,
						})
						break
					}
				}

				for _, frame := range currentMessage {
					sendFrame(conn, frame)
				}

				currentMessage = make([]WebsocketFrame, 0)
				isTextStream = false
			} else if !expectingFragment && frame.Fin && frame.Opcode != Continuation {
				//unfragmented frames
				expectingFragment = false

				if frame.Opcode == Text && !utf8.Valid(frame.Payload) {
					println("INVALID PAYLOAD")
					sendFrame(conn, WebsocketFrame{
						Fin:         true,
						Opcode:      ConnectionClose,
						Payload:     []byte{},
						ClosingCode: 1007,
					})
					break
				}

				sendFrame(conn, frame)
			} else {
				fmt.Printf("Unexpected frame pattern, FIN = %v Expecting Fragment = %v Opcode = %v\n", frame.Fin, expectingFragment, frame.Opcode)
				sendFrame(conn, WebsocketFrame{
					Fin:         true,
					Opcode:      ConnectionClose,
					Payload:     []byte{},
					ClosingCode: 1002,
					Rsv:         0,
				})
				break
			}
		}
	}
	closeSignal <- 0
}

func sendLoop(conn net.Conn, closeSignal chan int) {
	//time.Sleep(3 * time.Second)
	//var msg WebsocketMessage
	for {
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		//line := "xxabc123abc123x"

		if line == "close" {
			break
		}

		//build a unfragmented message
		sendFrame(conn, WebsocketFrame{
			Fin:     true,
			Opcode:  Text,
			Payload: []byte(line),
		})
	}
	closeSignal <- 0
}

func sendFrame(conn net.Conn, frame WebsocketFrame) {
	var header byte = 0
	//fin=1, rsv{1,2,3} = 0, opcode = 0
	header = 0
	if frame.Fin {
		header = 0b10000000
	}
	//opcode = text
	header |= byte(frame.Opcode)

	conn.Write([]byte{header})

	//mask is 1
	maskAndPayloadLen := byte(0b10000000)

	if frame.Opcode != ConnectionClose {
		payloadLen := len(frame.Payload)

		//8-byte
		if payloadLen > 65535 {
			maskAndPayloadLen |= byte(127)
		} else if payloadLen > 125 {
			maskAndPayloadLen |= byte(126)
		} else {
			maskAndPayloadLen |= byte(payloadLen)
		}

		conn.Write([]byte{maskAndPayloadLen})

		if payloadLen > 65535 {
			//send 8 bytes of length
			var uint64bytes [8]byte
			binary.BigEndian.PutUint64(uint64bytes[:], uint64(payloadLen))
			conn.Write(uint64bytes[:])
		} else if payloadLen > 125 {
			//send 2 bytes of length
			var uint16bytes [2]byte
			binary.BigEndian.PutUint16(uint16bytes[:], uint16(payloadLen))
			conn.Write(uint16bytes[:])
		}
		var maskKey [4]byte
		rand.Read(maskKey[:])

		conn.Write(maskKey[:])
		lineBytesMasked := []byte(frame.Payload)

		for i := range lineBytesMasked {
			lineBytesMasked[i] ^= maskKey[i%4]
		}

		conn.Write(lineBytesMasked)
	} else {
		maskAndPayloadLen |= byte(2)
		conn.Write([]byte{maskAndPayloadLen})

		var maskKey [4]byte
		rand.Read(maskKey[:])
		conn.Write(maskKey[:])

		var uint16bytes [2]byte
		binary.BigEndian.PutUint16(uint16bytes[:], uint16(frame.ClosingCode))

		for i := range uint16bytes {
			uint16bytes[i] ^= maskKey[i%4]
		}

		conn.Write(uint16bytes[:])
	}

}

func sendHandshake(conn net.Conn, endpoint string, domain string, port int) (int, string, error) {
	key := make([]byte, 16)
	rand.Read(key)
	secKey := base64.StdEncoding.EncodeToString(key)

	result, err := conn.Write([]byte(
		"GET " + endpoint + " HTTP/1.1\r\n" +
			"Host: " + domain + ":" + strconv.Itoa(port) + "\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Key: " + secKey + "\r\n" +
			"Sec-WebSocket-Version: 13\r\n" +
			"Sec-WebSocket-Protocol: echo\r\n" +
			"\r\n"))
	return result, secKey, err
}

func receiveHandshake(reader *bufio.Reader, secKey string) HttpPacket {
	var total []byte
	for {
		line, err := reader.ReadBytes(byte('\n'))
		if err != nil {
			panic(err)
		}
		total = append(total, line...)
		if len(line) == 2 && line[0] == 13 && line[1] == 10 {
			break
		}
	}
	response := string(total)
	parsed, err := parseHttpPacket(response)
	if err != nil {
		panic(err)
	}

	websocketValidate(secKey, parsed)

	return parsed
}

func getTestCases() int {
	domain := "127.0.0.1"
	port := 9001
	endpoint := "/getCaseCount"

	conn, reader, err := connectToWebsocket(domain, port, endpoint)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	frame, err := readWebsocketFrame(reader)
	if err != nil {
		panic(err)
	}

	i, err := strconv.Atoi(string(frame.Payload))
	if err != nil {
		panic(err)
	}
	return i
}

func connectToWebsocket(domain string, port int, endpoint string) (net.Conn, *bufio.Reader, error) {
	conn, err := net.Dial("tcp", domain+":"+strconv.Itoa(port))
	if err != nil {
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	_, secKey, err := sendHandshake(conn, endpoint, domain, port)
	if err != nil {
		return nil, nil, err
	}

	receiveHandshake(reader, secKey)
	return conn, reader, nil
}

func updateReports() {
	domain := "127.0.0.1"
	port := 9001
	endpoint := "/updateReports?agent=echo"

	conn, _, err := connectToWebsocket(domain, port, endpoint)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	sendFrame(conn, WebsocketFrame{
		Fin:         true,
		Opcode:      ConnectionClose,
		ClosingCode: 1000,
		Payload:     []byte{},
	})
}

func main() {
	cases := getTestCases()
	println(cases)
	domain := "127.0.0.1"
	port := 9001
	for i := 1; i < cases; i++ {

		fmt.Printf("\n############### \nRUNNING TEST %v\n###############\n\n", i)
		closeSignal := make(chan int)
		endpoint := "/runCase?case=" + strconv.Itoa(i) + "&agent=echo"

		conn, reader, err := connectToWebsocket(domain, port, endpoint)
		if err != nil {
			panic(err)
		}

		defer conn.Close()

		go runLoop(reader, conn, closeSignal)

		<-closeSignal
	}

	updateReports()
}
