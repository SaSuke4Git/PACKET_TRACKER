#!/usr/bin/env python3
"""
Network Packet Monitoring and Ethernet Frame Analysis System
------------------------------------------------------------
Data-link layer (OSI L2) monitor. Modes:

  sim   Generates Ethernet II frames (with VLAN, padding and a real CRC-32 FCS)
        and randomly corrupts some of them to demonstrate error detection.
  scapy Live capture via Scapy (Windows/Linux/macOS; Windows needs Npcap).
  live  Captures real frames from an interface (Linux, needs root, AF_PACKET).
        NOTE: most NICs strip the FCS before delivery, so error detection
        shows "N/A" for live frames.

Usage:
  python3 ethernet_monitor.py --mode sim --count 20 --error-rate 0.2
  python3 ethernet_monitor.py --mode sim --count 50 --csv frames.csv --seed 1
  sudo python3 ethernet_monitor.py --mode live --iface eth0 --count 30
  python3 ethernet_monitor.py --mode scapy --count 0 --pcap capture.pcap   (Ctrl+C to stop)
  python3 ethernet_monitor.py --gui
"""
import argparse, csv, itertools, random, socket, struct, sys, time, zlib
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Optional

MIN_PAYLOAD, MAX_PAYLOAD = 46, 1500
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
              0x8100: "802.1Q VLAN", 0x88CC: "LLDP", 0x8847: "MPLS"}
IP_PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP"}


# ---------------------------------------------------------------- helpers
def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))

def mac_to_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)

def compute_fcs(data: bytes) -> int:
    """IEEE 802.3 FCS = CRC-32 over dst..payload (zlib uses the same polynomial)."""
    return zlib.crc32(data) & 0xFFFFFFFF

def addr_class(dst: bytes) -> str:
    if dst == b"\xff" * 6:
        return "Broadcast"
    return "Multicast" if dst[0] & 1 else "Unicast"


# ---------------------------------------------------------------- frame builder
def build_frame(dst: str, src: str, ethertype: int, payload: bytes,
                vlan: Optional[int] = None, corrupt: bool = False) -> bytes:
    """Build a complete frame including padding and FCS (little-endian, as on the wire)."""
    payload = payload[:MAX_PAYLOAD]
    header = mac_to_bytes(dst) + mac_to_bytes(src)
    if vlan is not None:
        header += struct.pack("!HH", 0x8100, vlan & 0x0FFF)
    header += struct.pack("!H", ethertype)
    body = payload.ljust(MIN_PAYLOAD, b"\x00")          # pad to 46 bytes minimum
    fcs = struct.pack("<I", compute_fcs(header + body))
    frame = bytearray(header + body + fcs)
    if corrupt:                                          # flip one random bit
        i = random.randrange(len(frame))
        frame[i] ^= 1 << random.randrange(8)
    return bytes(frame)


MAC_POOL = []   # fixed set of simulated devices -> realistic per-source statistics

def init_mac_pool(n):
    MAC_POOL.clear()
    pool = [random_mac() for _ in range(n)]
    MAC_POOL.extend(pool)

def random_mac(multicast=False) -> str:
    if MAC_POOL and not multicast:
        return random.choice(MAC_POOL)
    first = random.randrange(0, 256) & 0xFC | (1 if multicast else 0)
    return mac_to_str(bytes([first]) + bytes(random.randrange(256) for _ in range(5)))


def ipv4_packet(proto: int, size: int) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + size, random.randrange(65536), 0,
                      64, proto, 0,
                      bytes([192, 168, 1, random.randint(2, 254)]),
                      bytes([10, 0, random.randint(0, 5), random.randint(2, 254)]))
    return hdr + bytes(random.randrange(256) for _ in range(size))


def arp_packet() -> bytes:
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1,
                       mac_to_bytes(random_mac()), bytes([192, 168, 1, 10]),
                       b"\x00" * 6, bytes([192, 168, 1, 1]))


def generate_random_frame(error_rate: float) -> bytes:
    kind = random.choices(["ipv4", "arp", "ipv6", "lldp"], weights=[70, 15, 10, 5])[0]
    dst = random_mac(multicast=random.random() < 0.1)
    if kind == "arp":
        dst, et, pl = "ff:ff:ff:ff:ff:ff", 0x0806, arp_packet()
    elif kind == "ipv4":
        et, pl = 0x0800, ipv4_packet(random.choice([1, 6, 17]), random.randint(8, 1400))
    elif kind == "ipv6":
        et, pl = 0x86DD, bytes(random.randrange(256) for _ in range(random.randint(40, 600)))
    else:
        dst, et, pl = "01:80:c2:00:00:0e", 0x88CC, bytes(random.randrange(256) for _ in range(40))
    vlan = random.choice([None, None, None, 10, 20, 100])
    return build_frame(dst, random_mac(), et, pl, vlan, corrupt=random.random() < error_rate)


# ---------------------------------------------------------------- parser
@dataclass
class FrameInfo:
    no: int
    time: str
    dst: str
    src: str
    addr_type: str
    ethertype: str
    vlan: str
    frame_len: int
    payload_len: int
    fcs_rx: str
    fcs_calc: str
    status: str
    detail: str


def parse_frame(raw: bytes, no: int, has_fcs: bool) -> FrameInfo:
    ts = time.strftime("%H:%M:%S")
    if len(raw) < 14:
        return FrameInfo(no, ts, "-", "-", "-", "-", "-", len(raw), 0, "-", "-",
                         "RUNT", "Frame shorter than 14-byte header")
    dst, src = raw[0:6], raw[6:12]
    et = struct.unpack("!H", raw[12:14])[0]
    off, vlan = 14, "-"
    if et == 0x8100 and len(raw) >= 18:
        tci, et = struct.unpack("!HH", raw[14:18])
        vlan, off = str(tci & 0x0FFF), 18

    status, fcs_rx, fcs_calc = "N/A", "-", "-"
    end = len(raw)
    if has_fcs and len(raw) >= off + 4:
        end = len(raw) - 4
        rx = struct.unpack("<I", raw[end:])[0]
        calc = compute_fcs(raw[:end])
        fcs_rx, fcs_calc = f"{rx:08x}", f"{calc:08x}"
        status = "OK" if rx == calc else "CRC ERROR"
    payload = raw[off:end]

    flags = []
    if has_fcs and len(raw) < 64:
        flags.append("runt (<64B)")
    if len(payload) > MAX_PAYLOAD:
        flags.append("oversize (>1500B payload)")
    if status == "OK" and flags:
        status = "WARN"

    detail = ""
    if et == 0x0800 and len(payload) >= 20:
        proto = IP_PROTOS.get(payload[9], str(payload[9]))
        detail = f"{socket.inet_ntoa(payload[12:16])} -> {socket.inet_ntoa(payload[16:20])} {proto}"
    elif et == 0x0806 and len(payload) >= 28:
        op = struct.unpack("!H", payload[6:8])[0]
        detail = (f"ARP {'request' if op == 1 else 'reply'} who-has "
                  f"{socket.inet_ntoa(payload[24:28])} tell {socket.inet_ntoa(payload[14:18])}")
    if flags:
        detail = (detail + " " if detail else "") + "[" + ", ".join(flags) + "]"

    return FrameInfo(no, ts, mac_to_str(dst), mac_to_str(src), addr_class(dst),
                     ETHERTYPES.get(et, f"0x{et:04x}"), vlan, len(raw), len(payload),
                     fcs_rx, fcs_calc, status, detail)


# ---------------------------------------------------------------- sources
def sim_source(count, error_rate, delay, stop=None):
    for _ in (range(count) if count else itertools.count()):
        if stop and stop():
            return
        yield generate_random_frame(error_rate), True
        time.sleep(delay)


def live_source(iface, count):
    if not hasattr(socket, "AF_PACKET"):
        sys.exit("Live capture needs Linux (AF_PACKET). Use --mode sim on this OS.")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if iface:
            s.bind((iface, 0))
    except PermissionError:
        sys.exit("Permission denied: run with sudo/root for live capture.")
    for _ in (range(count) if count else itertools.count()):
        yield s.recv(65535), False       # NIC normally strips the FCS


SCAPY_HELP = "Scapy not installed. Run: pip install scapy   (Windows also needs Npcap: https://npcap.com)"

def scapy_source(iface, count, stop=None):
    """Cross-platform live capture using Scapy. count=0 -> until stopped."""
    try:
        from scapy.all import sniff
    except ImportError:
        raise RuntimeError(SCAPY_HELP)
    n = 0
    while (not count or n < count) and not (stop and stop()):
        for pkt in sniff(iface=iface, count=1, timeout=1):
            n += 1
            yield bytes(pkt), False          # captured frames normally have no FCS


def write_pcap(path, records):
    """records: [(unix_time, raw_bytes)]. Classic libpcap file, LINKTYPE_ETHERNET."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, raw in records:
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(raw), len(raw)))
            fh.write(raw)


def passes_filter(f, mac="", etype=""):
    if mac and mac.lower() not in f.src and mac.lower() not in f.dst:
        return False
    return not etype or etype.lower() in f.ethertype.lower()


# ---------------------------------------------------------------- display
HEADER = (f"{'#':>3} {'Time':8} {'Destination':17} {'Source':17} {'Type':12} "
          f"{'VLAN':>4} {'Len':>5} {'Payload':>7} {'FCS rx/calc':17} {'Status':9} Detail")

def row(f: FrameInfo) -> str:
    fcs = f"{f.fcs_rx}/{f.fcs_calc}" if f.fcs_rx != "-" else "-"
    return (f"{f.no:>3} {f.time:8} {f.dst:17} {f.src:17} {f.ethertype:12} "
            f"{f.vlan:>4} {f.frame_len:>5} {f.payload_len:>7} {fcs:17} {f.status:9} {f.detail}")

def summary(frames):
    n = len(frames)
    if not n:
        return
    total = sum(f.frame_len for f in frames)
    bad = sum(f.status == "CRC ERROR" for f in frames)
    print("\n" + "=" * 60 + "\nSUMMARY")
    print(f"Frames: {n}   Bytes: {total}   Avg size: {total / n:.1f}   "
          f"Largest: {max(f.frame_len for f in frames)}   Smallest: {min(f.frame_len for f in frames)}")
    print(f"CRC errors: {bad} ({100 * bad / n:.1f}%)")
    print("By type     :", dict(Counter(f.ethertype for f in frames)))
    print("By address  :", dict(Counter(f.addr_type for f in frames)))
    print("Top sources :", Counter(f.src for f in frames).most_common(3))


def main():
    ap = argparse.ArgumentParser(description="Ethernet frame monitor / analyzer")
    ap.add_argument("--mode", choices=["sim", "scapy", "live"], default="sim")
    ap.add_argument("--count", type=int, default=20, help="number of frames (0 = until Ctrl+C)")
    ap.add_argument("--error-rate", type=float, default=0.15, help="sim: fraction corrupted")
    ap.add_argument("--delay", type=float, default=0.0, help="sim: seconds between frames")
    ap.add_argument("--iface", help="scapy/live: interface name")
    ap.add_argument("--list-ifaces", action="store_true", help="list interfaces (needs Scapy)")
    ap.add_argument("--mac-pool", type=int, default=6, help="sim: number of simulated devices (0 = all random)")
    ap.add_argument("--filter-mac", default="", help="show only frames with this MAC (substring)")
    ap.add_argument("--filter-type", default="", help="show only this type, e.g. ARP, IPv4")
    ap.add_argument("--csv", help="export results to CSV file")
    ap.add_argument("--pcap", help="export frames to .pcap (open in Wireshark)")
    ap.add_argument("--seed", type=int, help="sim: random seed for repeatable runs")
    ap.add_argument("--gui", action="store_true", help="launch the graphical interface")
    a = ap.parse_args()

    if a.gui:
        from ethernet_gui import launch
        return launch()
    if a.list_ifaces:
        try:
            from scapy.all import conf
        except ImportError:
            sys.exit(SCAPY_HELP)
        print(conf.ifaces)
        return
    if a.seed is not None:
        random.seed(a.seed)
    init_mac_pool(a.mac_pool)
    if a.mode == "sim":
        src = sim_source(a.count, a.error_rate, a.delay)
    elif a.mode == "scapy":
        src = scapy_source(a.iface, a.count)
    else:
        src = live_source(a.iface, a.count)

    print(HEADER + "\n" + "-" * len(HEADER))
    frames, records = [], []
    try:
        for i, (raw, has_fcs) in enumerate(src, 1):
            f = parse_frame(raw, i, has_fcs)
            if not passes_filter(f, a.filter_mac, a.filter_type):
                continue
            frames.append(f)
            records.append((time.time(), raw))
            print(row(f))
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"Capture error: {e}")
    summary(frames)

    if a.csv and frames:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(asdict(frames[0]).keys()))
            w.writeheader()
            w.writerows(asdict(f) for f in frames)
        print(f"Saved {len(frames)} records to {a.csv}")
    if a.pcap and records:
        write_pcap(a.pcap, records)
        print(f"Saved {len(records)} frames to {a.pcap}")


if __name__ == "__main__":
    main()