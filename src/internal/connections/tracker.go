
package connections

import (
	"log"
	"sync"
	"time"
	"go-tracer/internal/structs"
	"go-tracer/internal/utils"
)

const (
	maxBufferSize = 40 * 1024 // 30KB limit defined in C++ probe code, taking extra 10KB as buffer.
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

// We process a tracker after atleast 30 seconds, and delete it after 60 seconds of connection close.

func (conn *Tracker) IsComplete(duration time.Duration) bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return conn.closeTimestamp!=0 && uint64(time.Now().UnixNano())-conn.closeTimestamp > uint64(duration.Nanoseconds())
}

func (conn *Tracker) IsInactive(duration time.Duration) bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return uint64(time.Now().UnixNano())-conn.openTimestamp > uint64(duration.Nanoseconds())
}

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	bytesSent := (event.Attr.Bytes_sent>>32)>>16

	if bytesSent > 0 {
		conn.sentBuf = append(conn.sentBuf, event.Msg[:utils.Abs(bytesSent)]...)
		conn.sentBytes += uint64(utils.Abs(bytesSent))
	} else {
		conn.recvBuf = append(conn.recvBuf, event.Msg[:utils.Abs(bytesSent)]...)
		conn.recvBytes += uint64(utils.Abs(bytesSent))
	}
}

func (conn *Tracker) AddOpenEvent(event structs.SocketOpenEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.openTimestamp != 0 && conn.openTimestamp != event.ConnId.Conn_start_ns {
		log.Printf("Changed open info timestamp from %v to %v", conn.openTimestamp, event.ConnId.Conn_start_ns)
	}
	conn.openTimestamp = event.ConnId.Conn_start_ns
}

func (conn *Tracker) AddCloseEvent(event structs.SocketCloseEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	
	conn.closeTimestamp = uint64(time.Now().UnixNano())
}

