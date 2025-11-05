#!/usr/bin/env python3
from bcc import BPF
import docker
import sqlite3
from time import sleep
import ctypes
import sys

try:
    client = docker.from_env()
except Exception as e:
    print("Failed to initialize Docker client:", e)
    sys.exit(1)

def pid_to_container(pid):
    try:
        cgroup_path = f"/proc/{pid}/cgroup"
        with open(cgroup_path, "r") as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) == 3:
                    path = parts[2]
                    print(f"PID {pid} cgroup path: {path}", flush=True)
                    container_id = None
                    if "docker-" in path and ".scope" in path:
                        idx_start = path.find("docker-") + len("docker-")
                        idx_end = path.find(".scope", idx_start)
                        container_id = path[idx_start:idx_end]
                    elif "docker" in path:
                        container_id = path.split("docker/")[-1].split('/')[0]
                    elif "cri-containerd" in path:
                        container_id = path.split("cri-containerd/")[-1].split('/')[0]
                    elif "containerd" in path:
                        container_id = path.split("containerd/")[-1].split('/')[0]

                    if container_id:
                        for c in client.containers.list():
                            if c.id.startswith(container_id):
                                print(f"Matched container {c.name} for PID {pid}", flush=True)
                                return c.name
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Error reading cgroup path for PID {pid}: {e}", flush=True)
    return "host"

conn = sqlite3.connect("flows.db", timeout=5, check_same_thread=False)
cur = conn.cursor()
cur.execute("PRAGMA journal_mode = WAL;")
cur.execute("""
CREATE TABLE IF NOT EXISTS flows (
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    pid INT,
    container TEXT,
    saddr TEXT,
    sport INT,
    daddr TEXT,
    dport INT,
    proto INT
)
""")
conn.commit()

bpf_code = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 proto;
};
BPF_PERF_OUTPUT(events);

int kprobe__tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    u16 dport = 0;

    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);
    data.sport = sk->__sk_common.skc_num;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    data.dport = ntohs(dport);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.proto = 6;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

try:
    b = BPF(text=bpf_code)
except Exception as e:
    print("Failed to load BPF program:", e)
    sys.exit(1)

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("saddr", ctypes.c_uint),
        ("daddr", ctypes.c_uint),
        ("sport", ctypes.c_ushort),
        ("dport", ctypes.c_ushort),
        ("proto", ctypes.c_ubyte)
    ]

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    container_name = pid_to_container(event.pid)

    saddr = "%d.%d.%d.%d" % (
        event.saddr & 0xff,
        (event.saddr >> 8) & 0xff,
        (event.saddr >> 16) & 0xff,
        (event.saddr >> 24) & 0xff,
    )
    daddr = "%d.%d.%d.%d" % (
        event.daddr & 0xff,
        (event.daddr >> 8) & 0xff,
        (event.daddr >> 16) & 0xff,
        (event.daddr >> 24) & 0xff,
    )

    try:
        cur.execute(
            "INSERT INTO flows (pid, container, saddr, sport, daddr, dport, proto) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event.pid, container_name, saddr, event.sport, daddr, event.dport, event.proto),
        )
        conn.commit()
    except sqlite3.OperationalError as e:
        print(f"SQLite error: {e}", flush=True)

b["events"].open_perf_buffer(print_event)

print("Starting container-aware TCP monitor. Ctrl+C to exit.", flush=True)
try:
    while True:
        b.perf_buffer_poll()
        sleep(0.1)
except KeyboardInterrupt:
    print("Exiting...")
    conn.close()
except Exception as e:
    print("Runtime error:", e)
    conn.close()

