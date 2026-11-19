package frag

import (
	"reflect"
	"testing"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestFragUDPMessage(t *testing.T) {
	type args struct {
		m       *protocol.UDPMessage
		maxSize int
	}
	tests := []struct {
		name string
		args args
		want []protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
				100,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
			},
		},
		{
			"2 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
				20,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("hel"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("lo"),
				},
			},
		},
		{
			"4 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("abcdefgh"),
				},
				19,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("ab"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("cd"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    2,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("ef"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    3,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("gh"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FragUDPMessage(tt.args.m, tt.args.maxSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FragUDPMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefragger(t *testing.T) {
	type args struct {
		m *protocol.UDPMessage
	}
	tests := []struct {
		name string
		args args
		want *protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      "test:123",
				Data:      []byte("hello"),
			},
		},
		{
			"frag 0 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("hello "),
				},
			},
			nil,
		},
		{
			"frag 0 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("moto"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      "test:123",
				Data:      []byte("hello moto"),
			},
		},
		{
			"frag 1 - 1/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 3,
					Addr:      "test:123",
					Data:      []byte("deco"),
				},
			},
			nil,
		},
		{
			"frag 1 - 2/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 3,
					Addr:      "test:123",
					Data:      []byte("*"),
				},
			},
			nil,
		},
		{
			"frag 1 - 3/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    2,
					FragCount: 3,
					Addr:      "test:123",
					Data:      []byte("27"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      "test:123",
				Data:      []byte("deco*27"),
			},
		},
		{
			"frag 2 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("shinsekai"),
				},
			},
			nil,
		},
		{
			"frag 3 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  244,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("what???"),
				},
			},
			nil,
		},
		{
			"frag 2 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte(" annaijo"),
				},
			},
			nil,
		},
		{
			"invalid id",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    88,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("shinsekai"),
				},
			},
			nil,
		},
		{
			"frag 2 - 1/2 re",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    0,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("shinsekai"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  233,
				FragID:    0,
				FragCount: 1,
				Addr:      "test:123",
				Data:      []byte("shinsekai annaijo"),
			},
		},
	}

	d := &Defragger{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.Feed(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Feed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFragUDPMessage_FragmentCountLimit(t *testing.T) {
	// UDPMessage.FragCount is a uint8 on the wire, so a message can never be
	// split into more than 255 fragments. FragUDPMessage must respect that
	// limit instead of wrapping the count and indexing past the slice.
	const maxPayloadSize = 16
	m := &protocol.UDPMessage{SessionID: 1, Addr: "a"}
	maxSize := m.HeaderSize() + maxPayloadSize

	t.Run("255 fragments", func(t *testing.T) {
		m.Data = make([]byte, maxPayloadSize*255)
		got := FragUDPMessage(m, maxSize)
		if len(got) != 255 {
			t.Fatalf("got %d fragments, want 255", len(got))
		}
		var data []byte
		for i, f := range got {
			if f.FragID != uint8(i) || f.FragCount != 255 {
				t.Fatalf("fragment %d: FragID=%d FragCount=%d", i, f.FragID, f.FragCount)
			}
			data = append(data, f.Data...)
		}
		if !reflect.DeepEqual(data, m.Data) {
			t.Error("reassembled data does not match the original")
		}
	})

	t.Run("256 fragments", func(t *testing.T) {
		m.Data = make([]byte, maxPayloadSize*256)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("FragUDPMessage panicked on >255 fragments: %v", r)
			}
		}()
		got := FragUDPMessage(m, maxSize)
		if got != nil {
			t.Errorf("got %d fragments, want nil (exceeds uint8 FragCount)", len(got))
		}
	})
}
