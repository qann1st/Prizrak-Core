//go:build with_zapret2

package zapret2

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sort"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestReleaseProfileProcessesTLSClientHello(t *testing.T) {
	path := "../../.github/release/zapret2/config.yaml"
	if os.Getenv("PRIZRAK_ZAPRET2_WIN_SMOKE") == "1" {
		path = "config.yaml"
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var profile struct {
		Proxies []struct {
			Zapret2 struct {
				TCP     []int    `yaml:"tcp-ports"`
				UDP     []int    `yaml:"udp-ports"`
				Options []string `yaml:"options"`
			}
		}
	}
	if err := yaml.NewDecoder(file).Decode(&profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.Proxies) == 0 {
		t.Fatal("release config has no proxies")
	}
	z2 := profile.Proxies[0].Zapret2
	cfg, err := parse(&Option{TCPPorts: z2.TCP, UDPPorts: z2.UDP, Options: z2.Options})
	if err != nil {
		t.Fatal(err)
	}
	hello := tlsClientHello(t, "www.youtube.com")
	const seq uint32 = 0xffffff80
	for _, segmented := range []bool{false, true} {
		name := "single segment"
		if segmented {
			name = "two segments"
		}
		t.Run(name, func(t *testing.T) {
			g, err := newGuest(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer g.close()
			parts := [][]byte{hello}
			if segmented {
				cut := len(hello) / 2
				parts = [][]byte{hello[:cut], hello[cut:]}
			}
			var (
				currentSeq = seq
				real       [][]byte
				fakes      int
			)
			for _, chunk := range parts {
				input := tlsTCPPacket(currentSeq, chunk)
				from, to, _, _ := packetEndpoints(input)
				result, err := g.process(input, true, func(packet []byte) bool {
					src, dst, tcp, ok := packetEndpoints(packet)
					return ok && tcp && src == from && dst == to
				})
				if err != nil {
					t.Fatal(err)
				}
				if result.keep {
					real = append(real, input)
				}
				for _, packet := range result.packets {
					end := 20 + int(packet[32]>>4)*4
					if end < 40 || end > len(packet) {
						t.Fatalf("invalid output TCP header length: %d", end)
					}
					if bytes.Contains(packet[40:end], []byte{19, 18}) {
						fakes++
					} else {
						real = append(real, packet)
					}
				}
				currentSeq += uint32(len(chunk))
			}
			if fakes == 0 || len(real) < 2 {
				t.Fatalf("profile did not emit its fake and split segments (fake=%d, real=%d)", fakes, len(real))
			}
			sort.Slice(real, func(i, j int) bool {
				return binary.BigEndian.Uint32(real[i][24:28])-seq < binary.BigEndian.Uint32(real[j][24:28])-seq
			})
			reassembled := make([]byte, 0, len(hello))
			for _, packet := range real {
				reassembled = append(reassembled, packet[20+int(packet[32]>>4)*4:]...)
			}
			if !bytes.Equal(hello, reassembled) {
				t.Fatalf("strategy altered the real ClientHello: got %d bytes, want %d", len(reassembled), len(hello))
			}
		})
	}
	t.Run("host outside profile", func(t *testing.T) {
		g, err := newGuest(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer g.close()
		input := tlsTCPPacket(seq, tlsClientHello(t, "www.example.com"))
		result, err := g.process(input, true, func([]byte) bool { return true })
		if err != nil || !result.keep || len(result.packets) != 0 {
			t.Fatalf("unrelated TLS flow was changed: keep=%v, emitted=%d, err=%v", result.keep, len(result.packets), err)
		}
	})
}

func tlsClientHello(t *testing.T, host string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _ = tls.Client(client, &tls.Config{ServerName: host}).Handshake() }()
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	return append(header, body...)
}

func tlsTCPPacket(seq uint32, data []byte) []byte {
	packet := []byte{
		0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 10, 198, 51, 100, 10,
		0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 200, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
	}
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)+len(data)))
	binary.BigEndian.PutUint32(packet[24:28], seq)
	return append(packet, data...)
}
