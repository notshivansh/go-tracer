#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpconnect    Trace TCP connect()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpconnect [-h] [-c] [-t] [-p PID] [-P PORT [PORT ...]] [-4 | -6]
#
# All connection attempts are traced, even if they ultimately fail.
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Sep-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.
# 09-Jan-2019   Takuma Kume     Support filtering by UID
# 30-Jul-2019   Xiaozhou Liu    Count connects.
# 07-Oct-2020   Nabil Schear    Correlate connects with DNS responses
# 08-Mar-2021   Suresh Kumar    Added LPORT option

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep
from datetime import datetime
import json
from http.client import HTTPResponse, responses
from http.server import BaseHTTPRequestHandler
import time
from io import BytesIO
# from confluent_kafka import Producer
from time import sleep

examples = """examples:
    ./tcpconnect           # trace all TCP connect()s
    ./tcpconnect -t        # include timestamps
    ./tcpconnect -d        # include DNS queries associated with connects
    ./tcpconnect -p 181    # only trace PID 181
    ./tcpconnect -P 80     # only trace port 80
    ./tcpconnect -P 80,81  # only trace port 80 and 81
    ./tcpconnect -4        # only trace IPv4 family
    ./tcpconnect -6        # only trace IPv6 family
    ./tcpconnect -U        # include UID
    ./tcpconnect -u 1000   # only trace UID 1000
    ./tcpconnect -c        # count connects per src ip and dest ip/port
    ./tcpconnect -L        # include LPORT while printing outputs
    ./tcpconnect --cgroupmap mappath  # only trace cgroups in this BPF map
    ./tcpconnect --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-P", "--port",
    help="comma-separated list of destination ports to trace.")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("-L", "--lport", action="store_true",
    help="include LPORT on output")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="include UID on output")
parser.add_argument("-u", "--uid",
    help="trace this UID only")
parser.add_argument("-c", "--count", action="store_true",
    help="count connects per src ip and dest ip/port")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-d", "--dns", action="store_true",
    help="include likely DNS query associated with each connect")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
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



#define MAX_BUF_SIZE 400 

struct probe_SSL_data_t {
        u64 timestamp_ns;
        u64 delta_ns;
        u32 pid;
        u32 tid;
        u32 uid;
        u32 len;
        int buf_filled;
        int rw;
        u32 fd;
        char comm[TASK_COMM_LEN];
        u8 buf[MAX_BUF_SIZE];
};

#define BASE_EVENT_SIZE ((size_t)(&((struct probe_SSL_data_t*)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))

BPF_PERCPU_ARRAY(ssl_data, struct probe_SSL_data_t, 1);
BPF_PERF_OUTPUT(perf_SSL_rw);

BPF_HASH(start_ns, u32);
BPF_HASH(bufs, u32, u64);
BPF_HASH(fds, u32, u32);

BPF_HASH(active_ssl_read_args_map, uint64_t, struct data_args_t);
BPF_HASH(active_ssl_write_args_map, uint64_t, struct data_args_t);

static u32 get_fd(void *ssl){
    int32_t SSL_rbio_offset = 0x10;  // 0x10;
    int32_t RBIO_num_offset = 0x28;  // 0x30 (openssl 1.1.1) or 0x28 (openssl 1.1.0)
    
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

int probe_entry_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  char* bufc = (char*)PT_REGS_PARM2(ctx);
  u32 fd = get_fd(ssl);

  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.buf = bufc;
  active_ssl_write_args_map.update(&id, &write_args);

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, write_args.fd);

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

int probe_entry_SSL_read(struct pt_regs *ctx, void *ssl, void *buf, int num) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  char* bufc = (char*)PT_REGS_PARM2(ctx);
  int32_t fd = get_fd(ssl);

  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.buf = bufc;
  active_ssl_read_args_map.update(&id, &read_args);

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, read_args.fd);

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

int probe_SSL_rw_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        int ret;
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid;
        u32 uid = bpf_get_current_uid_gid();
        u64 ts = bpf_ktime_get_ns();

        int32_t SSL_rbio_offset = 0x10;  // 0x10;
        int32_t RBIO_num_offset = 0x28;  // 0x30 (openssl 1.1.1) or 0x28 (openssl 1.1.0)
        
        const void** rbio_ptr_addr = ssl + SSL_rbio_offset;
        const void* rbio_ptr = *rbio_ptr_addr;
        const int* rbio_num_addr = rbio_ptr + RBIO_num_offset;
        u32 rbio_num = *rbio_num_addr;

        //bpf_trace_printk("fd: &d", rbio_num);
        fds.update(&tid, &rbio_num);
        bufs.update(&tid, (u64*)&buf);
        start_ns.update(&tid, &ts);
        return 0;
}

static int SSL_exit(struct pt_regs *ctx, int rw) {
        int ret;
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u32 uid = bpf_get_current_uid_gid();
        u64 ts = bpf_ktime_get_ns();


        u64 *bufp = bufs.lookup(&tid);
        if (bufp == 0)
                return 0;

        u64 *tsp = start_ns.lookup(&tid);
        if (tsp == 0)
                return 0;

        int len = PT_REGS_RC(ctx);
        if (len <= 0) // no data
                return 0;

        struct probe_SSL_data_t *data = ssl_data.lookup(&zero);
        if (!data)
                return 0;

        u32 *fd = fds.lookup(&tid);
        if ( fd==0 )
            return 0;

        data->timestamp_ns = ts;
        data->delta_ns = ts - *tsp;
        data->pid = pid;
        data->tid = tid;
        data->uid = uid;
        data->len = (u32)len;
        data->buf_filled = 0;
        data->rw = rw;
        data->fd = *fd;
        u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);

        bpf_get_current_comm(&data->comm, sizeof(data->comm));

        if (bufp != 0)
                ret = bpf_probe_read_user(&data->buf, buf_copy_size, (char *)*bufp);

        bufs.delete(&tid);
        start_ns.delete(&tid);
        fds.delete(&tid);

        if (!ret)
                data->buf_filled = 1;
        else
                buf_copy_size = 0;

        perf_SSL_rw.perf_submit(ctx, data, EVENT_SIZE(buf_copy_size));
        return 0;
}

int probe_SSL_read_exit(struct pt_regs *ctx) {
        return (SSL_exit(ctx, 0));
}

int probe_SSL_write_exit(struct pt_regs *ctx) {
        return (SSL_exit(ctx, 1));
}

BPF_PERF_OUTPUT(perf_SSL_do_handshake);

int probe_SSL_do_handshake_enter(struct pt_regs *ctx, void *ssl) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u64 ts = bpf_ktime_get_ns();
        u32 uid = bpf_get_current_uid_gid();

        bpf_trace_printk("something");
        start_ns.update(&tid, &ts);
        return 0;
}

int probe_SSL_do_handshake_exit(struct pt_regs *ctx) {
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u32 uid = bpf_get_current_uid_gid();
        u64 ts = bpf_ktime_get_ns();
        int ret;


        u64 *tsp = start_ns.lookup(&tid);
        if (tsp == 0)
                return 0;

        ret = PT_REGS_RC(ctx);
        if (ret <= 0) // handshake failed
                return 0;

        struct probe_SSL_data_t *data = ssl_data.lookup(&zero);
        if (!data)
                return 0;

        data->timestamp_ns = ts;
        data->delta_ns = ts - *tsp;
        data->pid = pid;
        data->tid = tid;
        data->uid = uid;
        data->len = ret;
        data->buf_filled = 0;
        data->rw = 2;
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        start_ns.delete(&tid);
        bpf_trace_printk("something");
        perf_SSL_do_handshake.perf_submit(ctx, data, EVENT_SIZE(0));
        return 0;
}



"""

print("main start")

b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("accept")
print(execve_fnname)
b.attach_kprobe(event=execve_fnname, fn_name="syscall__probe_entry_accept")
b.attach_kretprobe(event=execve_fnname, fn_name="syscall__probe_ret_accept")

execve_fnname = b.get_syscall_fnname("accept4")
print(execve_fnname)
b.attach_kprobe(event=execve_fnname, fn_name="syscall__probe_entry_accept")
b.attach_kretprobe(event=execve_fnname, fn_name="syscall__probe_ret_accept")

execve_fnname = b.get_syscall_fnname("close")
print(execve_fnname)
b.attach_kprobe(event=execve_fnname, fn_name="syscall__probe_entry_close")
b.attach_kretprobe(event=execve_fnname, fn_name="syscall__probe_ret_close")

execve_fnname = b.get_syscall_fnname("recvfrom")
print(execve_fnname)
b.attach_kprobe(event=execve_fnname, fn_name="syscall__probe_entry_recvfrom")
b.attach_kretprobe(event=execve_fnname, fn_name="syscall__probe_ret_recvfrom")

execve_fnname = b.get_syscall_fnname("read")
print(execve_fnname)
b.attach_kprobe(event=execve_fnname, fn_name="syscall__probe_entry_recvfrom")
b.attach_kretprobe(event=execve_fnname, fn_name="syscall__probe_ret_recvfrom")

execve_fnname = b.get_syscall_fnname("sendto")
print(execve_fnname)
b.attach_kprobe(event=execve_fnname, fn_name="syscall__probe_entry_sendto")
b.attach_kretprobe(event=execve_fnname, fn_name="syscall__probe_ret_sendto")

execve_fnname = b.get_syscall_fnname("write")
print(execve_fnname)
b.attach_kprobe(event=execve_fnname, fn_name="syscall__probe_entry_sendto")
b.attach_kretprobe(event=execve_fnname, fn_name="syscall__probe_ret_sendto")


# the version of libssl may vary from system to system. 
# it should be calculated and used.
b.attach_uprobe(name="/usr/lib64/ssl/libssl.so.10", sym="SSL_write", fn_name="probe_entry_SSL_write", pid=-1)
b.attach_uretprobe(name="/usr/lib64/ssl/libssl.so.10", sym="SSL_write", fn_name="probe_ret_SSL_write", pid=-1)
b.attach_uprobe(name="/usr/lib64/ssl/libssl.so.10", sym="SSL_read", fn_name="probe_entry_SSL_read", pid=-1)
b.attach_uretprobe(name="/usr/lib64/ssl/libssl.so.10", sym="SSL_read", fn_name="probe_ret_SSL_read", pid=-1)

# save and process data to be sent to kafka
originalData = {}

class FakeSocket():
    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)
    def makefile(self, *args, **kwargs):
        return self._file

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

# producer = Producer({'bootstrap.servers': 'localhost:29092'})
# size = 1000000

# def send_to_kafka(msg):
#     producer.produce(
#         "akto.api.logs",
#         msg,
#         callback=lambda err, decoded_message, original_message=msg: delivery_report(  # noqa
#             err, decoded_message, original_message
#         ),
#     )

def process_raw_data(key):
    http_response_bytes = originalData[key]['sent'].encode()
    http_request_bytes = originalData[key]['recv'].encode()
    source = FakeSocket(http_response_bytes)
    response = HTTPResponse(source)
    response.begin()
    request = HTTPRequest(http_request_bytes)
    ret_data = {
        "path": request.path,
        "requestHeaders": dict(request.headers), 
        "responseHeaders": dict(response.getheaders()) , 
        "method": request.command,
        "requestPayload": request.rfile.read(len(http_request_bytes)).decode(), 
        "responsePayload": response.read(len(http_response_bytes)).decode(), 
        "ip": "", 
        "time": int(time.time()), 
        "statusCode": response.status,
        "type":request.request_version,
        "status": responses[response.status],
        "akto_account_id": "1000000", 
        "akto_vxlan_id": "123",  
        "is_pending" :"false",
        "source":"EBPF"
    }
    print(ret_data)
    # send_to_kafka(res_data)

keys_to_process = set()

def process_data():
    global keys_to_process
    temp_keys = set() 
    for temp_key in keys_to_process:
        if temp_key not in originalData:
            continue
        if(originalData[temp_key]['lastProcessedTime'] + 30 < int(time.time())):
            # use try catch here.
            try:
                process_raw_data(temp_key)
            except:
                print("dropped")
            temp_keys.add(temp_key)
    keys_to_process -= temp_keys

def print_accept(cpu, data, size):
    event = b["socket_open_events"].event(data)
    key = str(event.id) + '-' + str(event.fd) + '-' + str(event.conn_start_ns) + '-' + str(256*(event.port%256) + (event.port//256)) + '-' + str(event.ip)     
    originalData[key] = {
        'recv': '',
        'sent': '',
        'lastProcessedTime': 0
    }
    print("accept: " + key)
    # print("open: ", event.id, event.fd, event.conn_start_ns, 256*(event.port%256) + (event.port//256), event.ip, event.socket_open_ns)

def print_close(cpu, data, size):
    event = b["socket_close_events"].event(data)
    key = str(event.id) + '-' + str(event.fd) + '-' + str(event.conn_start_ns) + '-' + str(256*(event.port%256) + (event.port//256)) + '-' + str(event.ip) 
    print("close: " + key)
    # process_raw_data(key)
    keys_to_process.add(key)
    # print("close:", event.id, event.fd, event.conn_start_ns, 256*(event.port%256) + (event.port//256), event.ip, event.socket_close_ns)

def print_data(cpu, data, size):
    event = b["socket_data_events"].event(data)
    key = str(event.id) + '-' + str(event.fd) + '-' + str(event.conn_start_ns) + '-' + str(256*(event.port%256) + (event.port//256)) + '-' + str(event.ip) 
    # print('c ' + key + ' ' + str(event.bytes_sent))

    msg = event.msg.decode('utf-8', 'replace')
    methods = ['POST', 'GET', 'PUT']
    protocols = ['HTTP']

    if key in originalData and len(originalData[key]["sent" if event.bytes_sent > 0 else "recv"])>0:
        originalData[key]["sent" if event.bytes_sent > 0 else "recv"] += msg
    else :
        if (event.bytes_sent > 0 and not msg.startswith(tuple(protocols))) or (event.bytes_sent < 0 and not msg.startswith(tuple(methods))):
            return
        originalData[key]["sent" if event.bytes_sent > 0 else "recv"] = msg
    originalData[key]['lastProcessedTime'] = int(time.time())
    # print("data: " + key)
    # process_data(key)
    # print(("sent" if event.bytes_sent > 0 else "recv"), ":", event.id, event.fd, event.conn_start_ns, 256*(event.port%256) + (event.port//256), event.ip, event.bytes_sent, event.msg.decode('utf-8', 'replace'))

def print_event_rw(cpu, data, size):
    print("print rw")
    print_event(cpu, data, size, "perf_SSL_rw")

def print_event_handshake(cpu, data, size):
    print("print handshake")
    print_event(cpu, data, size, "perf_SSL_do_handshake")

def print_event(cpu, data, size, evt):
    global start
    event = b[evt].event(data)
    # print(event.pid, event.tid, event.timestamp_ns, event.delta_ns, event.uid, event.rw, event.len, event.buf_filled, event.fd)
    if event.len <= 400: 
        buf_size = event.len
    else:
        buf_size = 400 

    if event.buf_filled == 1:
        buf = bytearray(event.buf[:buf_size])
    else:
        buf_size = 0
        buf = b""

    # Filter events by command

    truncated_bytes = event.len - buf_size

    data = buf.decode('utf-8', 'replace')
    print(data)


print("main start 2")

# read events
b["socket_open_events"].open_perf_buffer(print_accept)
b["socket_data_events"].open_perf_buffer(print_data)
# b["perf_SSL_do_handshake"].open_perf_buffer(print_event_handshake)
# b["perf_SSL_rw"].open_perf_buffer(print_event_rw)
b["socket_close_events"].open_perf_buffer(print_close)

while 1:
    # print("started")
    b.perf_buffer_poll()
    process_data()
    # print("finished")
    # print(b.trace_fields())
