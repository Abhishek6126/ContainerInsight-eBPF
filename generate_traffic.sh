#!/bin/bash
set -e

echo "Generating diversified network traffic from containers..."

# Intra-network HTTP ping from nginx containers to others (nginx + redis)
for i in $(seq 1 8); do
  docker exec nginx$i curl -s http://nginx$(( (i % 8) + 1 )) >/dev/null || true
  docker exec nginx$i curl -s http://redis$(( (i % 8) + 1 )) >/dev/null || true
done

# Busybox containers wget to nginx
for i in $(seq 1 8); do
  docker exec busybox$i wget -qO- http://nginx$(( (i % 8) + 1 )) >/dev/null || true
done

# Alpine wget to nginx
for i in $(seq 1 8); do
  docker exec alpine1 wget -qO- http://nginx$i >/dev/null || true
done

# Redis ping self and other redis containers
for i in $(seq 1 8); do
  docker exec redis$i redis-cli ping >/dev/null || true
  docker exec redis$i redis-cli -h redis$(( (i % 8) + 1 )) ping >/dev/null || true
done

# Netshoot performing network fetches and pings (including external)
for i in $(seq 1 3); do
  docker exec netshoot$i curl -s http://nginx1 >/dev/null || true
  docker exec netshoot$i wget -qO- http://redis1 >/dev/null || true
  docker exec netshoot$i curl -s http://example.com >/dev/null || true
  docker exec netshoot$i ping -c 1 8.8.8.8 >/dev/null || true
done

# Simulate anomalous external traffic from some containers
docker exec busybox2 wget -qO- http://malicious.com >/dev/null || true
docker exec busybox3 wget -qO- http://example.com >/dev/null || true
docker exec alpine1 wget -qO- http://bad.hacker >/dev/null || true

echo "Traffic generation completed."

