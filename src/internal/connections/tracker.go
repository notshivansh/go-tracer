
package connections

import (
	"log"
	"sync"
	"time"
	"go-tracer/internal/structs"
)

const (
	maxBufferSize = 30 * 1024 // 30KB, same as the limit defined in C++ probe code.
)

type Tracker struct {
	connID structs.ConnID

	openTimestamp  uint64
	closeTimestamp uint64

	// Indicates the tracker stopped tracking due to closing the session.
	sentBytes             uint64
	recvBytes             uint64

	recvBuf []byte
	sentBuf []byte
	mutex   sync.RWMutex
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:  connID,
		recvBuf: make([]byte, 0, maxBufferSize),
		sentBuf: make([]byte, 0, maxBufferSize),
		mutex:   sync.RWMutex{},
	}
}

func (conn *Tracker) IsComplete() bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return conn.closeTimestamp != 0
}

func Abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	bytesSent := (event.Attr.Bytes_sent>>32)>>16

	if bytesSent > 0 {
		conn.sentBuf = append(conn.sentBuf, event.Msg[:Abs(bytesSent)]...)
		conn.sentBytes += uint64(Abs(bytesSent))
	} else {
		conn.recvBuf = append(conn.recvBuf, event.Msg[:Abs(bytesSent)]...)
		conn.recvBytes += uint64(Abs(bytesSent))
	}
}

func (conn *Tracker) AddOpenEvent(event structs.SocketOpenEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.openTimestamp != 0 && conn.openTimestamp != event.Conn_start_ns {
		log.Printf("Changed open info timestamp from %v to %v", conn.openTimestamp, event.Conn_start_ns)
	}
	conn.openTimestamp = event.Conn_start_ns
}

func (conn *Tracker) AddCloseEvent(event structs.SocketCloseEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	
	conn.closeTimestamp = event.Conn_start_ns + uint64(time.Now().Unix())
}
