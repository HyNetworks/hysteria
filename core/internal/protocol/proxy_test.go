package protocol

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestUDPMessage(t *testing.T) {
	t.Run("buffer too small", func(t *testing.T) {
		// Make sure Serialize returns -1 when the buffer is too small.
		tBuf := make([]byte, 20)
		if (&UDPMessage{
			SessionID: 66,
			PacketID:  77,
			FragID:    2,
			FragCount: 5,
			Addr:      "random_addr",
			Data:      []byte("random_data"),
		}).Serialize(tBuf) != -1 {
			t.Error("Serialize() did not return -1 when the buffer was too small")
		}
	})

	type fields struct {
		SessionID uint32
		PacketID  uint16
		FragID    uint8
		FragCount uint8
		Addr      string
		Data      []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name: "test 1",
			fields: fields{
				SessionID: 1,
				PacketID:  1,
				FragID:    0,
				FragCount: 1,
				Addr:      "example.com:80",
				Data:      []byte("GET /nothing HTTP/1.1\r\n"),
			},
			want: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0xe, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x38, 0x30, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa},
		},
		{
			name: "test 2",
			fields: fields{
				SessionID: 1329655244,
				Addr:      "some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long:9000",
				PacketID:  62233,
				FragID:    8,
				FragCount: 19,
				Data:      []byte("God is great, beer is good, and people are crazy."),
			},
			want: []byte{0x4f, 0x40, 0xed, 0xcc, 0xf3, 0x19, 0x8, 0x13, 0x41, 0xee, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x3a, 0x39, 0x30, 0x30, 0x30, 0x47, 0x6f, 0x64, 0x20, 0x69, 0x73, 0x20, 0x67, 0x72, 0x65, 0x61, 0x74, 0x2c, 0x20, 0x62, 0x65, 0x65, 0x72, 0x20, 0x69, 0x73, 0x20, 0x67, 0x6f, 0x6f, 0x64, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x70, 0x65, 0x6f, 0x70, 0x6c, 0x65, 0x20, 0x61, 0x72, 0x65, 0x20, 0x63, 0x72, 0x61, 0x7a, 0x79, 0x2e},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &UDPMessage{
				SessionID: tt.fields.SessionID,
				Addr:      tt.fields.Addr,
				PacketID:  tt.fields.PacketID,
				FragID:    tt.fields.FragID,
				FragCount: tt.fields.FragCount,
				Data:      tt.fields.Data,
			}
			// Serialize
			buf := make([]byte, MaxUDPSize)
			n := m.Serialize(buf)
			if got := buf[:n]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Serialize() = %v, want %v", got, tt.want)
			}
			// Parse back
			if m2, err := ParseUDPMessage(tt.want); err != nil {
				t.Errorf("ParseUDPMessage() error = %v", err)
			} else {
				if !reflect.DeepEqual(m2, m) {
					t.Errorf("ParseUDPMessage() = %v, want %v", m2, m)
				}
			}
		})
	}
}

// TestUDPMessageMalformed is to make sure ParseUDPMessage() fails (but not panic) on malformed data.
func TestUDPMessageMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "zeroes 1",
			data: []byte{0, 0, 0, 0},
		},
		{
			name: "zeroes 2",
			data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "incomplete 1",
			data: []byte{0x66, 0xCC, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
		{
			name: "incomplete 2",
			data: []byte{0x66, 0xCC, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x90, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseUDPMessage(tt.data); err == nil {
				t.Errorf("ParseUDPMessage() should fail")
			}
		})
	}
}

func TestParseUDPMessageReuseAddr(t *testing.T) {
	serialize := func(addr string) []byte {
		m := &UDPMessage{SessionID: 1, FragCount: 1, Addr: addr, Data: []byte("data")}
		buf := make([]byte, MaxUDPSize)
		return buf[:m.Serialize(buf)]
	}

	msg := serialize("example.com:443")
	first, err := ParseUDPMessageReuseAddr(msg, "")
	if err != nil {
		t.Fatalf("ParseUDPMessageReuseAddr() error = %v", err)
	}
	if first.Addr != "example.com:443" {
		t.Errorf("Addr = %q", first.Addr)
	}
	// Same address: lastAddr itself is returned
	second, err := ParseUDPMessageReuseAddr(serialize("example.com:443"), first.Addr)
	if err != nil {
		t.Fatalf("ParseUDPMessageReuseAddr() error = %v", err)
	}
	if unsafe.StringData(second.Addr) != unsafe.StringData(first.Addr) {
		t.Errorf("Addr should be the string passed in")
	}
	// Different address
	third, err := ParseUDPMessageReuseAddr(serialize("example.org:443"), second.Addr)
	if err != nil {
		t.Fatalf("ParseUDPMessageReuseAddr() error = %v", err)
	}
	if third.Addr != "example.org:443" {
		t.Errorf("Addr = %q", third.Addr)
	}
	// The address must not alias the message buffer
	copy(msg, make([]byte, len(msg)))
	if first.Addr != "example.com:443" {
		t.Errorf("Addr refers to the message buffer")
	}
}

func BenchmarkParseUDPMessage(b *testing.B) {
	m := &UDPMessage{SessionID: 1, FragCount: 1, Addr: "203.0.113.1:53", Data: make([]byte, 1200)}
	buf := make([]byte, MaxUDPSize)
	msg := buf[:m.Serialize(buf)]
	b.Run("new addr", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ParseUDPMessage(msg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("same addr", func(b *testing.B) {
		b.ReportAllocs()
		lastAddr := ""
		for b.Loop() {
			parsed, err := ParseUDPMessageReuseAddr(msg, lastAddr)
			if err != nil {
				b.Fatal(err)
			}
			lastAddr = parsed.Addr
		}
	})
}

func TestReadTCPRequest(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name:    "normal no padding",
			data:    []byte("\x0egoogle.com:443\x00"),
			want:    "google.com:443",
			wantErr: false,
		},
		{
			name:    "normal with padding",
			data:    []byte("\x0bholy.cc:443\x02gg"),
			want:    "holy.cc:443",
			wantErr: false,
		},
		{
			name:    "incomplete 1",
			data:    []byte("\x0bhoho"),
			want:    "",
			wantErr: true,
		},
		{
			name:    "incomplete 2",
			data:    []byte("\x0bholy.cc:443\x05x"),
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := ReadTCPRequest(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadTCPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadTCPRequest() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteTCPRequest(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantW   string // Just a prefix, we don't care about the padding
		wantErr bool
	}{
		{
			name:    "normal 1",
			addr:    "google.com:443",
			wantW:   "\x44\x01\x0egoogle.com:443",
			wantErr: false,
		},
		{
			name:    "normal 2",
			addr:    "client-api.arkoselabs.com:8080",
			wantW:   "\x44\x01\x1eclient-api.arkoselabs.com:8080",
			wantErr: false,
		},
		{
			name:    "empty",
			addr:    "",
			wantW:   "\x44\x01\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WriteTCPRequest(w, tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTCPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); !(strings.HasPrefix(gotW, tt.wantW) && len(gotW) > len(tt.wantW)) {
				t.Errorf("WriteTCPRequest() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestReadTCPResponse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    bool
		want1   string
		wantErr bool
	}{
		{
			name:    "normal ok no padding",
			data:    []byte("\x00\x0bhello world\x00"),
			want:    true,
			want1:   "hello world",
			wantErr: false,
		},
		{
			name:    "normal error with padding",
			data:    []byte("\x01\x06stop!!\x05xxxxx"),
			want1:   "stop!!",
			wantErr: false,
		},
		{
			name:    "normal ok no message with padding",
			data:    []byte("\x01\x00\x05xxxxx"),
			want1:   "",
			wantErr: false,
		},
		{
			name:    "incomplete 1",
			data:    []byte("\x00\x0bhoho"),
			want1:   "",
			wantErr: true,
		},
		{
			name:    "incomplete 2",
			data:    []byte("\x01\x05jesus\x05x"),
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, got1, err := ReadTCPResponse(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadTCPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadTCPResponse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ReadTCPResponse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestWriteTCPResponse(t *testing.T) {
	type args struct {
		ok  bool
		msg string
	}
	tests := []struct {
		name    string
		args    args
		wantW   string // Just a prefix, we don't care about the padding
		wantErr bool
	}{
		{
			name:    "normal ok",
			args:    args{ok: true, msg: "hello world"},
			wantW:   "\x00\x0bhello world",
			wantErr: false,
		},
		{
			name:    "normal error",
			args:    args{ok: false, msg: "stop!!"},
			wantW:   "\x01\x06stop!!",
			wantErr: false,
		},
		{
			name:    "empty",
			args:    args{ok: true, msg: ""},
			wantW:   "\x00\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WriteTCPResponse(w, tt.args.ok, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTCPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); !(strings.HasPrefix(gotW, tt.wantW) && len(gotW) > len(tt.wantW)) {
				t.Errorf("WriteTCPResponse() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
