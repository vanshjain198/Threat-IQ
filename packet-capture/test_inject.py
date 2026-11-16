"""
test_inject.py — Quick test: inject sample packets directly into the backend
without needing the packet capture module or Scapy.

Usage:
    python test_inject.py
    python test_inject.py --url http://localhost:3001
"""

import argparse
import requests
import time
import random

BACKEND = "http://localhost:3001/api/analyze"

SAMPLES = [
    # Normal HTTP browse
    dict(protocol_type=1, src_bytes=1200, dst_bytes=4800,
         serror_rate=0.0, same_srv_rate=0.9, count=5,
         src_ip="192.168.1.10", dst_ip="10.0.0.1",
         src_port=52431, dst_port=80, protocol="TCP"),

    # Neptune DoS
    dict(protocol_type=1, src_bytes=0, dst_bytes=0,
         serror_rate=0.99, srv_serror_rate=0.99, count=511,
         same_srv_rate=1.0, diff_srv_rate=0.0,
         src_ip="203.0.113.42", dst_ip="10.0.0.5",
         src_port=31337, dst_port=80, protocol="TCP"),

    # Portsweep
    dict(protocol_type=1, src_bytes=0, dst_bytes=0,
         serror_rate=0.0, same_srv_rate=0.07, diff_srv_rate=0.81,
         count=200, srv_count=10,
         src_ip="198.51.100.7", dst_ip="10.0.0.5",
         src_port=45000, dst_port=22, protocol="TCP"),

    # Guess password R2L
    dict(protocol_type=1, src_bytes=200, dst_bytes=0,
         num_failed_logins=6, logged_in=0, count=6,
         serror_rate=0.0, same_srv_rate=1.0,
         src_ip="172.16.5.100", dst_ip="10.0.0.1",
         src_port=49200, dst_port=22, protocol="TCP"),

    # Buffer overflow U2R
    dict(protocol_type=1, src_bytes=1408, dst_bytes=0,
         root_shell=1, su_attempted=1, hot=2,
         src_ip="192.168.1.200", dst_ip="10.0.0.1",
         src_port=60000, dst_port=514, protocol="TCP"),

    # Normal DNS
    dict(protocol_type=2, src_bytes=64, dst_bytes=128,
         serror_rate=0.0, same_srv_rate=1.0, count=3,
         src_ip="192.168.1.15", dst_ip="8.8.8.8",
         src_port=53421, dst_port=53, protocol="UDP"),

    # Smurf DoS
    dict(protocol_type=0, src_bytes=936, dst_bytes=0,
         serror_rate=0.0, count=511, same_srv_rate=1.0,
         src_ip="10.0.0.255", dst_ip="10.0.0.1",
         src_port=0, dst_port=0, protocol="ICMP"),
]


def inject(url, n, delay):
    print(f"\n🧪  Injecting {n} test packets → {url}")
    print(f"   Delay: {delay}s between packets\n")

    sent = 0
    for i in range(n):
        pkt = random.choice(SAMPLES).copy()
        # Randomise IPs slightly
        pkt["src_ip"] = f"192.168.{random.randint(1,5)}.{random.randint(1,254)}"

        try:
            r = requests.post(url, json=pkt, timeout=4)
            if r.status_code == 200:
                res = r.json().get("result", {})
                tag  = "🔴 ATTACK" if res.get("is_attack") else "🟢 normal"
                pred = res.get("prediction", "?")
                conf = res.get("confidence", 0)
                print(f"  [{i+1:3d}] {pkt['src_ip']:15s} → {pkt['dst_ip']:10s}  "
                      f"{tag}  {pred:<20s}  {conf:.1f}%")
                sent += 1
            else:
                print(f"  [{i+1:3d}] HTTP {r.status_code}: {r.text[:60]}")
        except requests.exceptions.ConnectionError:
            print(f"  ✗  Cannot reach backend at {url}")
            print("     Start the backend first: cd server && npm start")
            break
        except Exception as e:
            print(f"  ✗  {e}")

        time.sleep(delay)

    print(f"\n✅  Done — sent {sent}/{n} packets")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="NIDS test injector")
    p.add_argument("--url",   default=BACKEND, help="Backend analyze URL")
    p.add_argument("--count", type=int, default=20, help="Number of packets")
    p.add_argument("--delay", type=float, default=0.5, help="Seconds between packets")
    args = p.parse_args()
    inject(args.url, args.count, args.delay)
