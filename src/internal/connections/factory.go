
package connections

import (
	// "fmt"
	"sync"
	"time"
	"go-tracer/internal/structs"
	"github.com/segmentio/kafka-go"
)

// Factory is a routine-safe container that holds a trackers with unique ID, and able to create new tracker.
type Factory struct {
	connections         map[structs.ConnID]*Tracker
	inactivityThreshold time.Duration
	completeThreshold   time.Duration
	mutex               *sync.RWMutex
	maxActiveConnections int
}

// NewFactory creates a new instance of the factory.
func NewFactory(inactivityThreshold time.Duration, completeThreshold time.Duration, maxActiveConnections int) *Factory {
	return &Factory{
		connections:         make(map[structs.ConnID]*Tracker),
		mutex:               &sync.RWMutex{},
		inactivityThreshold: inactivityThreshold,
		completeThreshold:   completeThreshold,
		maxActiveConnections: maxActiveConnections,
	}
}

func (factory *Factory) HandleReadyConnections(kafkaWriter *kafka.Writer) {
	trackersToDelete := make(map[structs.ConnID]struct{})

	for connID, tracker := range factory.connections {
		if tracker.IsComplete(factory.completeThreshold) {
			trackersToDelete[connID] = struct{}{}
			if len(tracker.sentBuf) == 0 && len(tracker.recvBuf) == 0 {
				continue
			}
			if kafkaWriter != nil {
				tryReadFromBD(tracker, kafkaWriter)
			}
		} else if tracker.IsInactive(factory.inactivityThreshold) {
			trackersToDelete[connID] = struct{}{}
		}
	}
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	for key := range trackersToDelete {
		delete(factory.connections, key)
	}
}

// GetOrCreate returns a tracker that related to the given connection and transaction ids. If there is no such tracker
// we create a new one.
func (factory *Factory) GetOrCreate(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	tracker, ok := factory.connections[connectionID]
	if !ok {
		factory.connections[connectionID] = NewTracker(connectionID)
		return factory.connections[connectionID]
	}
	return tracker
}

func (factory *Factory) CanBeFilled() bool {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()
	return len(factory.connections) < factory.maxActiveConnections
}

// Get returns a tracker that related to the given connection and transaction ids. If there is no such tracker
// we create a new one.
func (factory *Factory) Get(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	return factory.connections[connectionID]
}
