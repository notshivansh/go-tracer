package main

import (
	// "bufio"
	"bytes"
	"encoding/binary"
	// "flag"
	// "fmt"
	"os"
	"os/signal"
	// "strconv"
	// "strings"
	"unsafe"
    // "io/ioutil"
	"log"
	"syscall"
	"time"
    "strings"
    "strconv"
	"github.com/iovisor/gobpf/bcc"

    "github.com/segmentio/kafka-go"
	"go-tracer/internal/bpfwrapper"
	"go-tracer/internal/connections"
	"go-tracer/internal/structs"
    "github.com/akto-api-security/gomiddleware"
)

import "C"

var source string = `
#include <bcc/proto.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>

#define socklen_t size_t
#define MAX_MSG_SIZE 30720

struct conn_info_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    bool ssl;
};

struct accept_args_t {
    struct sockaddr* addr;
};

struct data_args_t {
    u32 fd;
    const char* buf;
};

struct close_args_t {
    u32 fd;
};

struct socket_open_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    u64 socket_open_ns;
};

struct socket_close_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    u64 socket_close_ns;
};

struct socket_data_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    int bytes_sent;
    char msg[MAX_MSG_SIZE];
};

BPF_HASH(conn_info_map, u64, struct conn_info_t, 131072);

BPF_PERF_OUTPUT(socket_data_events);
BPF_PERF_OUTPUT(socket_open_events);
BPF_PERF_OUTPUT(socket_close_events);

BPF_PERCPU_ARRAY(socket_data_event_buffer_heap, struct socket_data_event_t, 1);

BPF_HASH(active_accept_args_map, u64, struct accept_args_t);
BPF_HASH(active_close_args_map, u64, struct close_args_t);
BPF_HASH(active_recvfrom_args_map, u64, struct data_args_t);
BPF_HASH(active_sendto_args_map, u64, struct data_args_t);
BPF_HASH(active_ssl_read_args_map, uint64_t, struct data_args_t);
BPF_HASH(active_ssl_write_args_map, uint64_t, struct data_args_t);

static __inline u64 gen_tgid_fd(u32 tgid, int fd) {
  return ((u64)tgid << 32) | (u32)fd;
}

static __inline void process_syscall_accept(struct pt_regs* ret, const struct accept_args_t* args, u64 id) {
    int ret_fd = PT_REGS_RC(ret);

    if (ret_fd < 0) {
        return;
    }

    if (args->addr->sa_family != AF_INET) {
        return;
    }

    struct sockaddr_in* sock_in = (struct sockaddr_in *)args->addr;

    struct conn_info_t conn_info = {};
    conn_info.id = id;
    conn_info.fd = ret_fd;
    conn_info.conn_start_ns = bpf_ktime_get_ns();

    conn_info.port = sock_in->sin_port;
    struct in_addr *in_addr_ptr = &(sock_in->sin_addr);
    conn_info.ip = in_addr_ptr->s_addr;
    conn_info.ssl = false;


    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, ret_fd);
    conn_info_map.update(&tgid_fd, &conn_info);

    struct socket_open_event_t socket_open_event = {};
    socket_open_event.id = conn_info.id;
    socket_open_event.fd = conn_info.fd;
    socket_open_event.conn_start_ns = conn_info.conn_start_ns;
    socket_open_event.port = conn_info.port;
    socket_open_event.ip = conn_info.ip;

    socket_open_event.socket_open_ns = conn_info.conn_start_ns;
    socket_open_events.perf_submit(ret, &socket_open_event, sizeof(struct socket_open_event_t));
}


static __inline void process_syscall_close(struct pt_regs* ret, const struct close_args_t* args, u64 id) {
    int ret_val = PT_REGS_RC(ret);

    if (ret_val < 0) {
        return;
    }

    if (args->fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;
    }

    struct socket_close_event_t socket_close_event = {};
    socket_close_event.id = conn_info->id;
    socket_close_event.fd = conn_info->fd;
    socket_close_event.conn_start_ns = conn_info->conn_start_ns;
    socket_close_event.port = conn_info->port;
    socket_close_event.ip = conn_info->ip;

    socket_close_event.socket_close_ns = bpf_ktime_get_ns();
    socket_close_events.perf_submit(ret, &socket_close_event, sizeof(struct socket_close_event_t));
    conn_info_map.delete(&tgid_fd);    
}

static __inline void process_syscall_data(struct pt_regs* ret, const struct data_args_t* args, u64 id, bool is_send, bool ssl) {
    int bytes_exchanged = PT_REGS_RC(ret);

    if (bytes_exchanged <= 0) {
        return;
    }

    if (args->fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;
    }
    bpf_trace_printk("something %d",conn_info->ssl);
    if (conn_info->ssl != ssl) {
        return;
    }


    u32 kZero = 0;
    struct socket_data_event_t* socket_data_event = socket_data_event_buffer_heap.lookup(&kZero);
    if (socket_data_event == NULL) {
        return;
    }

    
    socket_data_event->id = conn_info->id;
    socket_data_event->fd = conn_info->fd;
    socket_data_event->conn_start_ns = conn_info->conn_start_ns;
    socket_data_event->port = conn_info->port;
    socket_data_event->ip = conn_info->ip; 
    socket_data_event->bytes_sent = is_send ? 1 : -1;

    
    size_t bytes_exchanged_minus_1 = bytes_exchanged - 1;
    asm volatile("" : "+r"(bytes_exchanged_minus_1) :);
    bytes_exchanged = bytes_exchanged_minus_1 + 1;

    size_t size_to_save = 0;
    if (bytes_exchanged_minus_1 < MAX_MSG_SIZE) {
        bpf_probe_read(&socket_data_event->msg, bytes_exchanged, args->buf);
        size_to_save = bytes_exchanged;
        socket_data_event->msg[size_to_save] = '\\0';
    } else if (bytes_exchanged_minus_1 < 0x7fffffff) {
        bpf_probe_read(&socket_data_event->msg, MAX_MSG_SIZE, args->buf);
        size_to_save = MAX_MSG_SIZE;
    }

    
    socket_data_event->bytes_sent *= size_to_save;
    
    socket_data_events.perf_submit(ret, socket_data_event, sizeof(struct socket_data_event_t) - MAX_MSG_SIZE + size_to_save);

}


// Hooks
int syscall__probe_entry_accept(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    u64 id = bpf_get_current_pid_tgid();

    struct accept_args_t accept_args = {};
    accept_args.addr = addr;
    active_accept_args_map.update(&id, &accept_args);
    bpf_trace_printk("printing from accept");
    return 0;
}

int syscall__probe_ret_accept(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);

    if (accept_args != NULL) {
        process_syscall_accept(ctx, accept_args, id);
    }

    active_accept_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_close(struct pt_regs* ctx, int fd) {
    u64 id = bpf_get_current_pid_tgid();

    struct close_args_t close_args = {};
    close_args.fd = fd;
    active_close_args_map.update(&id, &close_args);
    
    return 0;
}

int syscall__probe_ret_close(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct close_args_t* close_args = active_close_args_map.lookup(&id);

    if (close_args != NULL) {
        process_syscall_close(ctx, close_args, id);
    }

    active_close_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_recvfrom(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();

    struct data_args_t recvfrom_args = {};
    recvfrom_args.buf = buf;
    recvfrom_args.fd = fd;
    active_recvfrom_args_map.update(&id, &recvfrom_args);
    
    return 0;
}

int syscall__probe_ret_recvfrom(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct data_args_t* recvfrom_args = active_recvfrom_args_map.lookup(&id);

    if (recvfrom_args != NULL) {
        process_syscall_data(ctx, recvfrom_args, id, false, false);
    }

    active_recvfrom_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_sendto(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();

    struct data_args_t sendto_args = {};
    sendto_args.buf = buf;
    sendto_args.fd = fd;
    active_sendto_args_map.update(&id, &sendto_args);
    
    return 0;
}

int syscall__probe_ret_sendto(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct data_args_t* sendto_args = active_sendto_args_map.lookup(&id);

    if (sendto_args != NULL) {
        process_syscall_data(ctx, sendto_args, id, true, false);
    }

    active_sendto_args_map.delete(&id);
    return 0;
}


int syscall__probe_entry_accept4(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    u64 id = bpf_get_current_pid_tgid();

    u32 pid = id >> 32;

    bpf_trace_printk("syscall__probe_entry_accept4: step 1: %d\\n", pid);
    return 0;
}

// Hooking the exit of accept4
int syscall__probe_ret_accept4(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    u32 pid = id >> 32;

    bpf_trace_printk("syscall__probe_ret_accept4: step 1: %d\\n", pid);
    return 0;
}

static u32 get_fd(void *ssl, bool isBoringSSL) {
    int32_t SSL_rbio_offset;
    int32_t RBIO_num_offset;
    
    if(isBoringSSL){
        SSL_rbio_offset = 0x18;
        RBIO_num_offset = 0x18;
    } else {
        SSL_rbio_offset = 0x10;
        RBIO_num_offset = RBIO_NUM_OFFSET;
    }

    const void** rbio_ptr_addr = ssl + SSL_rbio_offset;
    const void* rbio_ptr = *rbio_ptr_addr;
    const int* rbio_num_addr = rbio_ptr + RBIO_num_offset;
    u32 rbio_num = *rbio_num_addr;
    return rbio_num;
}

static void set_conn_as_ssl(u32 tgid, u32 fd){
    u64 tgid_fd = gen_tgid_fd(tgid, fd);
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;
    }
    conn_info->ssl = true;
}

static void probe_entry_SSL_write_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  char* bufc = (char*)PT_REGS_PARM2(ctx);

  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.buf = bufc;
  active_ssl_write_args_map.update(&id, &write_args);

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, write_args.fd);
}

int probe_entry_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, false);
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_write_boring(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, true);
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_ret_SSL_write(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  const struct data_args_t* write_args = active_ssl_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_syscall_data(ctx, write_args, id, true, true);
  }

  active_ssl_write_args_map.delete(&id);
  return 0;
}

static void probe_entry_SSL_read_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
    u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  char* bufc = (char*)PT_REGS_PARM2(ctx);

  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.buf = bufc;
  active_ssl_read_args_map.update(&id, &read_args);

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, read_args.fd);
}

int probe_entry_SSL_read(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, false);
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);

  return 0;
}

int probe_entry_SSL_read_boring(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, true);
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);

  return 0;
}

int probe_ret_SSL_read(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  const struct data_args_t* read_args = active_ssl_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_syscall_data(ctx, read_args, id, false, true);
  }

  active_ssl_read_args_map.delete(&id);
  return 0;
}

`

var (
	level1hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "accept",
			HookName:       "syscall__probe_entry_accept",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept",
			HookName:       "syscall__probe_ret_accept",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
        {
			FunctionToHook: "accept4",
			HookName:       "syscall__probe_entry_accept",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept4",
			HookName:       "syscall__probe_ret_accept",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}

	level2hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "recvfrom",
			HookName:       "syscall__probe_entry_recvfrom",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recvfrom",
			HookName:       "syscall__probe_ret_recvfrom",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
        {
			FunctionToHook: "recv",
			HookName:       "syscall__probe_entry_recvfrom",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recv",
			HookName:       "syscall__probe_ret_recvfrom",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
        {
			FunctionToHook: "read",
			HookName:       "syscall__probe_entry_recvfrom",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_ret_recvfrom",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}

	level3hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "sendto",
			HookName:       "syscall__probe_entry_sendto",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "sendto",
			HookName:       "syscall__probe_ret_sendto",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
        {
			FunctionToHook: "send",
			HookName:       "syscall__probe_entry_sendto",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "send",
			HookName:       "syscall__probe_ret_sendto",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
        {
			FunctionToHook: "write",
			HookName:       "syscall__probe_entry_sendto",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_ret_sendto",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}

	level4hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "close",
			HookName:       "syscall__probe_entry_close",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "close",
			HookName:       "syscall__probe_ret_close",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}

    sslHooks = []bpfwrapper.Uprobe{
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_SSL_write",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_SSL_write",
			Type:           bpfwrapper.ReturnType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_SSL_read",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_SSL_read",
			Type:           bpfwrapper.ReturnType,
		},
        {
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_entry_SSL_write",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_ret_SSL_write",
			Type:           bpfwrapper.ReturnType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_entry_SSL_read",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_ret_SSL_read",
			Type:           bpfwrapper.ReturnType,
		},
    }

    boringsslHooks = []bpfwrapper.Uprobe{
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_SSL_write_boring",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_SSL_write",
			Type:           bpfwrapper.ReturnType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_SSL_read_boring",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_SSL_read",
			Type:           bpfwrapper.ReturnType,
		},
    }
)

func socketOpenEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketOpenEvent
		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data on socker open: %+v", err)
			continue
		}

        connId := event.ConnId
		connectionFactory.GetOrCreate(connId).AddOpenEvent(event)

        }
}

func socketCloseEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketCloseEvent
		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data on socket close: %+v", err)
			continue
		}

        connId := event.ConnId
		tracker := connectionFactory.Get(connId)
		if tracker == nil {
			continue
		}
		tracker.AddCloseEvent(event)

	}
}

var (
    // this also includes space lost in padding.
	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))
)

func Abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func socketDataEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketDataEvent

		// binary.Read require the input data to be at the same size of the object.
		// Since the Msg field might be mostly empty, binary.read fails.
		// So we split the loading into the fixed size attribute parts, and copying the message separately.

		if err := binary.Read(bytes.NewReader(data[:eventAttributesSize]), bcc.GetHostByteOrder(), &event.Attr); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}

        // this value was observed.
        bytesSent := (event.Attr.Bytes_sent>>32)>>16

        // The 4 bytes are being lost in padding, thus, not taking them into consideration.
        eventAttributesLogicalSize := 36

		if len(data) > eventAttributesLogicalSize {
			copy(event.Msg[:], data[eventAttributesLogicalSize:eventAttributesLogicalSize+int(Abs(bytesSent))])
		}

        connId := event.Attr.ConnId
		connectionFactory.GetOrCreate(connId).AddDataEvent(event)

        // fmt.Println("<------------")
        // fmt.Printf("Got data event of size %v, with data: %s", event.Attr.Bytes_sent, event.Msg[:Abs(bytesSent)])
        // fmt.Println("------------>")
	}
}


func replaceOpensslMacros(){
    opensslVersion := os.Getenv("OPENSSL_VERSION_AKTO")
    fixed := false
    if len(opensslVersion) > 0 {
        split := strings.Split(opensslVersion,".")
        if len(split) == 3 {
            if split[0] == "1" &&  ( split[1] == "0" || strings.HasPrefix(split[2],"0") ) {
                source = strings.Replace(source, "RBIO_NUM_OFFSET", "0x28",1)
                fixed = true
            }
        }
    }
    if !fixed {
        source = strings.Replace(source, "RBIO_NUM_OFFSET", "0x30",1)
    }
}

func initKafka() (kafkaWriter *kafka.Writer) {

    kafka_url := os.Getenv("AKTO_KAFKA_BROKER_MAL")
	log.Println("kafka_url", kafka_url)

	if len(kafka_url) == 0 {
		kafka_url = os.Getenv("AKTO_KAFKA_BROKER_URL")
	}
	log.Println("kafka_url", kafka_url)

	kafka_batch_size, e := strconv.Atoi(os.Getenv("AKTO_TRAFFIC_BATCH_SIZE"))
	if e != nil {
		log.Printf("AKTO_TRAFFIC_BATCH_SIZE should be valid integer")
		return
	}

	kafka_batch_time_secs, e := strconv.Atoi(os.Getenv("AKTO_TRAFFIC_BATCH_TIME_SECS"))
	if e != nil {
		log.Printf("AKTO_TRAFFIC_BATCH_TIME_SECS should be valid integer")
		return
	}
	kafka_batch_time_secs_duration := time.Duration(kafka_batch_time_secs)

	kafkaWriter = gomiddleware.GetKafkaWriter(kafka_url, "akto.api.logs", kafka_batch_size, kafka_batch_time_secs_duration*time.Second)
    
    return
}

func main() {
	run()
}

func run(){
	
    replaceOpensslMacros()

	bpfModule := bcc.NewModule(source, []string{})
    if bpfModule == nil {
		log.Panic("bpf is nil")
	}
	defer bpfModule.Close()

    var kafkaWriter *kafka.Writer

    kafkaWriter = initKafka()

    connectionFactory := connections.NewFactory(time.Minute)
	go func() {
		for {
			connectionFactory.HandleReadyConnections(kafkaWriter)
			time.Sleep(1 * time.Second)
		}
	}()

	callbacks := make([]*bpfwrapper.ProbeChannel, 0)

    hooks := make([]bpfwrapper.Kprobe, 0)
    callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_open_events", socketOpenEventCallback))
    hooks = append(hooks, level1hooks...)
    callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_data_events", socketDataEventCallback))
    hooks = append(hooks, level2hooks...)
    hooks = append(hooks, level3hooks...)
    callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_close_events", socketCloseEventCallback))
    hooks = append(hooks, level4hooks...)

    if err := bpfwrapper.LaunchPerfBufferConsumers(bpfModule, connectionFactory, callbacks); err != nil {
		log.Panic(err)
	}

	if err := bpfwrapper.AttachKprobes(bpfModule, hooks); err != nil {
		log.Panic(err)
	}

    opensslPath := os.Getenv("OPENSSL_PATH_AKTO")
    if len(opensslPath) > 0 {
        opensslPath = strings.Replace(opensslPath, "usr","usr_host",1)
        if err := bpfwrapper.AttachUprobes(opensslPath, -1, bpfModule, sslHooks); err != nil {
            log.Printf("%s",err.Error())
        }
    }

    boringLibsslPath := os.Getenv("BSSL_PATH_AKTO")
    if len(boringLibsslPath) > 0 {
        boringLibsslPath = strings.Replace(boringLibsslPath, "usr","usr_host",1)
        if err := bpfwrapper.AttachUprobes(boringLibsslPath, -1, bpfModule, boringsslHooks); err != nil {
            log.Printf("%s",err.Error())
        }
    }

    sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
    log.Println("Sniffer is ready")
	<-sig
	log.Println("Signaled to terminate")
}