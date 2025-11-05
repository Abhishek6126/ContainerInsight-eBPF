#!/bin/bash
set -e

echo "=== Step 0: Cleanup old containers and DB ==="
rm -f flows.db
docker ps -aq | xargs -r docker rm -f

echo "=== Step 1: Create Docker network ==="
docker network create mydemo-net || true

echo "=== Step 2: Start containers ==="
for i in $(seq 1 8); do
  docker run -d --rm --net mydemo-net --name nginx$i nginx
  docker run -d --rm --net mydemo-net --name redis$i redis
  docker run -d --rm --net mydemo-net --name busybox$i busybox sleep 300
done
docker run -d --rm --net mydemo-net --name alpine1 alpine sleep 300

echo "=== Step 3: Start netshoot containers ==="
for i in $(seq 1 3); do
  docker run -d --rm --net mydemo-net --name netshoot$i nicolaka/netshoot sleep 300
done

sleep 5

echo "=== Step 4: Install curl and wget ==="
docker exec nginx1 apt-get update || true
docker exec nginx1 apt-get install -y curl || true
docker exec alpine1 sh -c "apk add --no-cache wget" || true

echo "=== Step 5: Start the eBPF monitor in background ==="
sudo python3 tcp_monitor.py > flows.log 2>&1 &
EBPF_PID=$!

echo "=== Step 6: Start visualization in background ==="
#python3 visualize.py &
VIS_PID=$!

sleep 2

echo "=== Step 7: Start continuous traffic generation ==="
trap "echo 'Stopping demo...'; kill $EBPF_PID $VIS_PID; exit" INT TERM

while true; do
  for i in $(seq 1 8); do
    docker exec nginx$i curl -s http://nginx$(( (i % 8) + 1 )) >/dev/null || true
    docker exec nginx$i curl -s http://redis$(( (i % 8) + 1 )) >/dev/null || true
    docker exec busybox$i wget -qO- http://nginx$(( (i % 8) + 1 )) >/dev/null || true
    docker exec alpine1 wget -qO- http://nginx$i >/dev/null || true
    docker exec redis$i redis-cli ping >/dev/null || true
    docker exec redis$i redis-cli -h redis$(( (i % 8) + 1 )) ping >/dev/null || true
  done

  for i in $(seq 1 3); do
    docker exec netshoot$i curl -s http://nginx1 >/dev/null || true
    docker exec netshoot$i wget -qO- http://redis1 >/dev/null || true
    docker exec netshoot$i curl -s http://example.com >/dev/null || true
    docker exec netshoot$i ping -c 1 8.8.8.8 >/dev/null || true
  done

  # Anomalous traffic for demo
  docker exec busybox2 wget -qO- http://malicious.com >/dev/null || true
  docker exec busybox3 wget -qO- http://example.com >/dev/null || true
  docker exec alpine1 wget -qO- http://bad.hacker >/dev/null || true

  sleep 10
done

