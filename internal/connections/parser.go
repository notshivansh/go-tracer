package connections

import (
	"bufio"
	"bytes"
	"compress/gzip"
	// "context"
	"encoding/json"
	"fmt"
	// "github.com/akto-api-security/mirroring-api-logging/db"
	// "github.com/akto-api-security/mirroring-api-logging/utils"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	// "os"
	// "strconv"
	"time"

	// "github.com/google/gopacket"
	// "github.com/google/gopacket/layers"
	// "github.com/google/gopacket/pcap"
	// "github.com/google/gopacket/tcpassembly"

	// "github.com/akto-api-security/gomiddleware"
	"github.com/segmentio/kafka-go"
)


func tryReadFromBD(tracker *Tracker, kafkaWriter *kafka.Writer) {
	reader := bufio.NewReader(bytes.NewReader(tracker.recvBuf))
	i := 0
	requests := []http.Request{}
	requestsContent := []string{}

	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			log.Println("HTTP-request", "HTTP Request error: %s\n", err)
			return
		}
		body, err := ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			log.Println("HTTP-request-body", "Got body err: %s\n", err)
			return
		}

		requests = append(requests, *req)
		requestsContent = append(requestsContent, string(body))
		// log.Println("req.URL.String()", i, req.URL.String(), string(body), len(bd.a.bytes))
		i++
	}

	reader = bufio.NewReader(bytes.NewReader(tracker.sentBuf))
	i = 0
	log.Println("len(req)", len(requests))
	for {
		if len(requests) < i+1 {
			break
		}
		req := &requests[i]
		resp, err := http.ReadResponse(reader, req)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			log.Println("HTTP-request", "HTTP Request error: %s\n", err)
			return
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("HTTP-request-body", "Got body err: %s\n", err)
			return
		}
		encoding := resp.Header["Content-Encoding"]
		var r io.Reader
		r = bytes.NewBuffer(body)
		if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
			r, err = gzip.NewReader(r)
			if err != nil {
				log.Println("HTTP-gunzip", "Failed to gzip decode: %s", err)
				return
			}
		}
		if err == nil {
			body, err = ioutil.ReadAll(r)
			if _, ok := r.(*gzip.Reader); ok {
				r.(*gzip.Reader).Close()
			}

		}

		reqHeader := make(map[string]string)
		for name, values := range req.Header {
			// Loop over all values for the name.
			for _, value := range values {
				reqHeader[name] = value
			}
		}

		reqHeader["host"] = req.Host

		respHeader := make(map[string]string)
		for name, values := range resp.Header {
			// Loop over all values for the name.
			for _, value := range values {
				respHeader[name] = value
			}
		}

		reqHeaderString, _ := json.Marshal(reqHeader)
		respHeaderString, _ := json.Marshal(respHeader)

		value := map[string]string{
			"path":            req.URL.String(),
			"requestHeaders":  string(reqHeaderString),
			"responseHeaders": string(respHeaderString),
			"method":          req.Method,
			"requestPayload":  requestsContent[i],
			"responsePayload": string(body),
			"ip":              "",
			"time":            fmt.Sprint(time.Now().Unix()),
			"statusCode":      fmt.Sprint(resp.StatusCode),
			"type":            string(req.Proto),
			"status":          resp.Status,
			"akto_account_id": fmt.Sprint(1000000),
			"akto_vxlan_id":   "",
			"is_pending":      "false",
			"source":          "EBPF",
		}

		// out, _ := json.Marshal(value)
		// ctx := context.Background()

		// calculating the size of outgoing bytes and requests (1) and saving it in outgoingCounterMap
		// outgoingBytes := len(tracker.recvBuf) + len(tracker.sentBuf)
		// hostString := reqHeader["host"]
		// fmt.Printf("value: %v",value)
		for k, v := range value {
			fmt.Println(k, ":", v)
		}
		
		// if utils.CheckIfIpHost(hostString) {
		// 	hostString = "ip-host"
		// }
		// oc := utils.GenerateOutgoingCounter(bd.vxlanID, bd.key.net.Src().String(), hostString)
		// existingOc, ok := outgoingCountMap[oc.OutgoingCounterKey()]
		// if ok {
		// 	existingOc.Inc(outgoingBytes, 1)
		// } else {
		// 	oc.Inc(outgoingBytes, 1)
		// 	outgoingCountMap[oc.OutgoingCounterKey()] = oc
		// }

		// if printCounter > 0 {
		// 	printCounter--
		// 	log.Println("req-resp.String()", string(out))
		// }

		// go gomiddleware.Produce(kafkaWriter, ctx, string(out))

		i++
	}
}