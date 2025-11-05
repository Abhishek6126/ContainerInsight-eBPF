#!/usr/bin/env python3
import sqlite3
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation, PillowWriter
from collections import defaultdict
import time

DB_PATH = "flows.db"
conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
cur = conn.cursor()
cur.execute("PRAGMA journal_mode = WAL;")
conn.commit()

MALICIOUS_CONTAINERS = ["busybox2"]

def is_anomaly(container, daddr, dport):
    return container in MALICIOUS_CONTAINERS

def fetch_data():
    try:
        cur.execute("SELECT ts, container, daddr, dport FROM flows ORDER BY ts DESC LIMIT 200")
        rows = cur.fetchall()
    except sqlite3.OperationalError as e:
        print("DB locked, retrying...", e)
        time.sleep(0.1)
        return fetch_data()
    container_counts = defaultdict(int)
    for ts, container, daddr, dport in rows:
        container_counts[container] += 1
    return container_counts

# Initialize figure and axis
fig, ax = plt.subplots(figsize=(8, 8))

# Initialize scatter with empty data
scatter = ax.scatter([], [])

def animate(frame_idx):
    container_counts = fetch_data()
    container_counts_filtered = {c: n for c, n in container_counts.items() if c != "host"}
    if not container_counts_filtered:
        print("No data yet...")
        scatter.set_offsets(np.empty((0, 2)))
        return scatter,

    labels = list(container_counts_filtered.keys())
    sizes = np.array([container_counts_filtered[l] for l in labels])
    colors = np.array(['red' if l in MALICIOUS_CONTAINERS else 'green' for l in labels])

    # For scatter plot, position points on circle (example)
    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False)
    x = np.cos(angles)
    y = np.sin(angles)
    points = np.column_stack((x, y))

    scatter.set_offsets(points)
    scatter.set_color(colors)
    scatter.set_sizes(sizes * 100)  # Scale sizes for visibility

    ax.clear()
    ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
    ax.set_title("Container-wise TCP Flows (Red = Malicious)")
    ax.axis('equal')

    return scatter,

num_frames = 60
ani = FuncAnimation(fig, animate, frames=num_frames, interval=2000, repeat=False, cache_frame_data=False)

plt.show()

ani.save("container_flows.gif", writer=PillowWriter(fps=1))
print("GIF saved as container_flows.gif")

