package server

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/goleak"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestUDPSessionManager(t *testing.T) {
	io := newMockUDPIO(t)
	eventLogger := newMockUDPEventLogger(t)
	sm := newUDPSessionManager(io, eventLogger, 2*time.Second)

	msgCh := make(chan *protocol.UDPMessage, 4)
	io.EXPECT().ReceiveMessage().RunAndReturn(func() (*protocol.UDPMessage, error) {
		m := <-msgCh
		if m == nil {
			return nil, errors.New("closed")
		}
		return m, nil
	})

	go sm.Run()

	udpReadFunc := func(addr string, ch chan []byte, b []byte) (int, string, error) {
		bs := <-ch
		if bs == nil {
			return 0, "", errors.New("closed")
		}
		n := copy(b, bs)
		return n, addr, nil
	}

	// Test normal session creation & timeout
	msg1 := &protocol.UDPMessage{
		SessionID: 1234,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "address1.com:9000",
		Data:      []byte("hello"),
	}
	eventLogger.EXPECT().New(msg1.SessionID, msg1.Addr).Return().Once()
	udpConn1 := newMockUDPConn(t)
	udpConn1Ch := make(chan []byte, 1)
	io.EXPECT().Hook([][]byte{msg1.Data}, &msg1.Addr).Return(true, nil).Once()
	io.EXPECT().UDP(msg1.Addr).Return(udpConn1, nil).Once()
	udpConn1.EXPECT().WriteTo(msg1.Data, msg1.Addr).Return(5, nil).Once()
	udpConn1.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, string, error) {
		return udpReadFunc(msg1.Addr, udpConn1Ch, b)
	})
	io.EXPECT().SendMessage(mock.Anything, &protocol.UDPMessage{
		SessionID: msg1.SessionID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg1.Addr,
		Data:      []byte("hi back"),
	}).Return(nil).Once()
	msgCh <- msg1
	udpConn1Ch <- []byte("hi back")

	msg2data := []byte("how are you doing?")
	msg2_1 := &protocol.UDPMessage{
		SessionID: 5678,
		PacketID:  0,
		FragID:    0,
		FragCount: 2,
		Addr:      "address2.net:12450",
		Data:      msg2data[:6],
	}
	msg2_2 := &protocol.UDPMessage{
		SessionID: 5678,
		PacketID:  0,
		FragID:    1,
		FragCount: 2,
		Addr:      "address2.net:12450",
		Data:      msg2data[6:],
	}

	eventLogger.EXPECT().New(msg2_1.SessionID, msg2_1.Addr).Return().Once()
	udpConn2 := newMockUDPConn(t)
	udpConn2Ch := make(chan []byte, 1)
	// On fragmentation, make sure hook gets the whole message
	io.EXPECT().Hook([][]byte{msg2data}, &msg2_1.Addr).Return(true, nil).Once()
	io.EXPECT().UDP(msg2_1.Addr).Return(udpConn2, nil).Once()
	udpConn2.EXPECT().WriteTo(msg2data, msg2_1.Addr).Return(11, nil).Once()
	udpConn2.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, string, error) {
		return udpReadFunc(msg2_1.Addr, udpConn2Ch, b)
	})
	io.EXPECT().SendMessage(mock.Anything, &protocol.UDPMessage{
		SessionID: msg2_1.SessionID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg2_1.Addr,
		Data:      []byte("im fine"),
	}).Return(nil).Once()
	msgCh <- msg2_1
	msgCh <- msg2_2
	udpConn2Ch <- []byte("im fine")

	msg3 := &protocol.UDPMessage{
		SessionID: 1234,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "address1.com:9000",
		Data:      []byte("who are you?"),
	}
	udpConn1.EXPECT().WriteTo(msg3.Data, msg3.Addr).Return(12, nil).Once()
	io.EXPECT().SendMessage(mock.Anything, &protocol.UDPMessage{
		SessionID: msg3.SessionID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg3.Addr,
		Data:      []byte("im your father"),
	}).Return(nil).Once()
	msgCh <- msg3
	udpConn1Ch <- []byte("im your father")

	// Make sure timeout works (connections closed & close events emitted)
	udpConn1.EXPECT().Close().RunAndReturn(func() error {
		close(udpConn1Ch)
		return nil
	}).Once()
	udpConn2.EXPECT().Close().RunAndReturn(func() error {
		close(udpConn2Ch)
		return nil
	}).Once()
	eventLogger.EXPECT().Close(msg1.SessionID, nil).Once()
	eventLogger.EXPECT().Close(msg2_1.SessionID, nil).Once()

	time.Sleep(3 * time.Second) // Wait for timeout
	mock.AssertExpectationsForObjects(t, io, eventLogger, udpConn1, udpConn2)

	// Test UDP connection close error propagation
	errUDPClosed := errors.New("UDP connection closed")
	msg4 := &protocol.UDPMessage{
		SessionID: 666,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "oh-no.com:27015",
		Data:      []byte("dont say bye"),
	}
	eventLogger.EXPECT().New(msg4.SessionID, msg4.Addr).Return().Once()
	udpConn4 := newMockUDPConn(t)
	io.EXPECT().Hook([][]byte{msg4.Data}, &msg4.Addr).Return(true, nil).Once()
	io.EXPECT().UDP(msg4.Addr).Return(udpConn4, nil).Once()
	udpConn4.EXPECT().WriteTo(msg4.Data, msg4.Addr).Return(12, nil).Once()
	udpConn4.EXPECT().ReadFrom(mock.Anything).Return(0, "", errUDPClosed).Once()
	udpConn4.EXPECT().Close().Return(nil).Once()
	eventLogger.EXPECT().Close(msg4.SessionID, errUDPClosed).Once()
	msgCh <- msg4

	time.Sleep(1 * time.Second)
	mock.AssertExpectationsForObjects(t, io, eventLogger, udpConn4)

	// Test UDP connection creation error propagation
	errUDPIO := errors.New("UDP IO error")
	msg5 := &protocol.UDPMessage{
		SessionID: 777,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "callmemaybe.com:15353",
		Data:      []byte("babe i miss you"),
	}
	eventLogger.EXPECT().New(msg5.SessionID, msg5.Addr).Return().Once()
	io.EXPECT().Hook([][]byte{msg5.Data}, &msg5.Addr).Return(true, nil).Once()
	io.EXPECT().UDP(msg5.Addr).Return(nil, errUDPIO).Once()
	eventLogger.EXPECT().Close(msg5.SessionID, errUDPIO).Once()
	msgCh <- msg5

	time.Sleep(1 * time.Second)
	mock.AssertExpectationsForObjects(t, io, eventLogger)

	// Leak checks
	close(msgCh)                // This will return error from ReceiveMessage(), should stop the session manager
	time.Sleep(1 * time.Second) // Wait one more second just to be sure
	assert.Zero(t, sm.Count(), "session count should be 0")
	goleak.VerifyNone(t)
}

func TestUDPSessionManagerHookHold(t *testing.T) {
	io := newMockUDPIO(t)
	eventLogger := newMockUDPEventLogger(t)
	sm := newUDPSessionManager(io, eventLogger, 2*time.Second)

	msgCh := make(chan *protocol.UDPMessage, 4)
	io.EXPECT().ReceiveMessage().RunAndReturn(func() (*protocol.UDPMessage, error) {
		m := <-msgCh
		if m == nil {
			return nil, errors.New("closed")
		}
		return m, nil
	})

	go sm.Run()

	msg1 := &protocol.UDPMessage{SessionID: 42, FragCount: 1, Addr: "1.2.3.4:443", Data: []byte("first")}
	msg2 := &protocol.UDPMessage{SessionID: 42, FragCount: 1, Addr: "1.2.3.4:443", Data: []byte("second")}
	// The hook holds the first message back, and rewrites the address once it sees the second
	io.EXPECT().Hook([][]byte{msg1.Data}, &msg1.Addr).Return(false, nil).Once()
	io.EXPECT().Hook([][]byte{msg1.Data, msg2.Data}, &msg1.Addr).RunAndReturn(func(_ [][]byte, addr *string) (bool, error) {
		*addr = "example.com:443"
		return true, nil
	}).Once()
	eventLogger.EXPECT().New(msg1.SessionID, "example.com:443").Return().Once()
	udpConn := newMockUDPConn(t)
	udpConnCh := make(chan []byte, 1)
	io.EXPECT().UDP("example.com:443").Return(udpConn, nil).Once()
	mock.InOrder(
		udpConn.EXPECT().WriteTo(msg1.Data, "example.com:443").Return(5, nil).Call,
		udpConn.EXPECT().WriteTo(msg2.Data, "example.com:443").Return(6, nil).Call,
	)
	udpConn.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, string, error) {
		bs := <-udpConnCh
		if bs == nil {
			return 0, "", errors.New("closed")
		}
		return copy(b, bs), "93.184.215.14:443", nil
	})
	// Replies come from the original address
	replied := make(chan struct{})
	io.EXPECT().SendMessage(mock.Anything, &protocol.UDPMessage{
		SessionID: msg1.SessionID,
		FragCount: 1,
		Addr:      msg1.Addr,
		Data:      []byte("reply"),
	}).RunAndReturn(func([]byte, *protocol.UDPMessage) error {
		close(replied)
		return nil
	}).Once()
	msgCh <- msg1
	msgCh <- msg2
	udpConnCh <- []byte("reply")
	<-replied

	udpConn.EXPECT().Close().RunAndReturn(func() error {
		close(udpConnCh)
		return nil
	}).Once()
	eventLogger.EXPECT().Close(msg1.SessionID, nil).Once()

	// Wait for timeout
	assert.Eventually(t, func() bool { return sm.Count() == 0 }, 5*time.Second, 100*time.Millisecond)
	mock.AssertExpectationsForObjects(t, io, eventLogger, udpConn)

	close(msgCh)
	time.Sleep(1 * time.Second)
	goleak.VerifyNone(t)
}
