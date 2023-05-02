/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0.
 */

package connections

import (
	// "fmt"
	// "go-tracer/internal/settings"
	"sync"
	"time"
	// "bufio"
    // "bytes"
    // "io"
    // "io/ioutil"
    // "log"
    // "net/http"
    // "net/http/httputil"

	"go-tracer/internal/structs"
	"github.com/segmentio/kafka-go"
)

// Factory is a routine-safe container that holds a trackers with unique ID, and able to create new tracker.
type Factory struct {
	connections         map[structs.ConnID]*Tracker
	inactivityThreshold time.Duration
	mutex               *sync.RWMutex
}

// NewFactory creates a new instance of the factory.
func NewFactory(inactivityThreshold time.Duration) *Factory {
	return &Factory{
		connections:         make(map[structs.ConnID]*Tracker),
		mutex:               &sync.RWMutex{},
		inactivityThreshold: inactivityThreshold,
	}
}

// type Connection struct {
//     Request  *http.Request
//     Response *http.Response
// }

// func ReadHTTPData(tracker *Tracker) ([]Connection, error) {
//     bufR := bufio.NewReader(bytes.NewReader(tracker.recvBuf))
// 	bufS := bufio.NewReader(bytes.NewReader(tracker.sendBuf))
//     stream := make([]Connection, 0)

//     for {
//         req, err := http.ReadRequest(bufR)
//         if err == io.EOF {
//             break
//         }
//         if err != nil {
//             return stream, err
//         }

//         resp, err := http.ReadResponse(bufS, req)
//         if err != nil {
//             return stream, err
//         }

//         //save response body
//         b := new(bytes.Buffer)
//         io.Copy(b, resp.Body)
//         resp.Body.Close()
//         resp.Body = ioutil.NopCloser(b)

//         stream = append(stream, Connection{Request: req, Response: resp})
//     }
//     return stream, nil

// }


func (factory *Factory) HandleReadyConnections(kafkaWriter *kafka.Writer) {
	trackersToDelete := make(map[structs.ConnID]struct{})

	for connID, tracker := range factory.connections {
		if tracker.IsComplete() {
			trackersToDelete[connID] = struct{}{}
			if len(tracker.sentBuf) == 0 && len(tracker.recvBuf) == 0 {
				continue
			}
			// if !settings.DebugLog {
			// 	fmt.Printf("========================>\nFound HTTP payload\nRequest->\n%s\n\nResponse->\n%s\n\n<========================\n", tracker.recvBuf, tracker.sentBuf)
			// }

			tryReadFromBD(tracker, kafkaWriter)
			// stream, err := ReadHTTPFromFile(tracker)
			// if err != nil {
			// 	log.Fatalln(err)
			// }
			// for _, c := range stream {
			// 	b, err := httputil.DumpRequest(c.Request, true)
			// 	if err != nil {
			// 		log.Fatal(err)
			// 	}
			// 	fmt.Println(string(b))
			// 	b, err = httputil.DumpResponse(c.Response, true)
			// 	if err != nil {
			// 		log.Fatal(err)
			// 	}
			// 	fmt.Println(string(b))
			// }

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

// Get returns a tracker that related to the given connection and transaction ids. If there is no such tracker
// we create a new one.
func (factory *Factory) Get(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	return factory.connections[connectionID]
}
