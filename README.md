# Network Packet Monitoring and Ethernet Frame Analysis System

A Python-based Ethernet frame monitoring and analysis tool for learning and demonstrating Data Link Layer (OSI Layer 2) concepts. It generates simulated Ethernet frames, injects bit errors, parses frame fields, checks CRC-32/FCS when available, captures live traffic with Scapy, and displays results in a Tkinter GUI.

## Features

- Simulates Ethernet II traffic for IPv4, ARP, IPv6, and LLDP.
- Builds frames with minimum payload padding and optional IEEE 802.1Q VLAN tags.
- Demonstrates CRC-32/FCS error detection by flipping a random bit after calculating the FCS.
- Parses source/destination MAC addresses, EtherType, VLAN ID, frame length, payload length, and status.
- Classifies destination MAC addresses as unicast, multicast, or broadcast.
- Filters by protocol type and MAC address.
- Displays frame statistics and a protocol chart.
- Shows selected frames as hexadecimal bytes.
- Exports decoded data to CSV and raw frames to PCAP.
- Supports live capture using Scapy on supported platforms.

## Project Structure

Keep both Python files in the same directory:

```text
project/
├── ethernet_monitor.py   # Core frame generation, parsing, CRC, filtering and export
├── ethernet_gui.py       # Tkinter graphical interface
└── README.md
```

**Important:** The core file must be named `ethernet_monitor.py`, because the GUI imports it using `import ethernet_monitor as core`.

## Requirements

- Python 3.8 or later
- Tkinter (usually included with standard Python installations)
- Scapy for live capture (optional)
- Npcap on Windows for live packet capture

Simulation mode does not require Scapy or Npcap.

## Installation

### 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
```

Replace the placeholders with your repository URL and folder name.

### 2. Install Scapy (optional; required for live capture)

```bash
python -m pip install scapy
```

On Windows, install [Npcap](https://npcap.com/) as well. Live capture may require administrator/root privileges.

## Run the Project

### Launch the graphical interface

```bash
python ethernet_gui.py
```

### Run the command-line simulator

```bash
python ethernet_monitor.py --mode sim --count 20 --error-rate 0.2
```

### Filter for ARP frames

```bash
python ethernet_monitor.py --mode sim --count 50 --filter-type ARP
```

### Export simulated frames

```bash
python ethernet_monitor.py --mode sim --count 50 --csv frames.csv --pcap capture.pcap
```

### List capture interfaces (Scapy required)

```bash
python ethernet_monitor.py --list-ifaces
```

### Capture live traffic using Scapy

```bash
python ethernet_monitor.py --mode scapy --iface "Wi-Fi" --count 100 --pcap capture.pcap
```

Replace `Wi-Fi` with an interface name shown by `--list-ifaces`. Linux interface names may look like `eth0` or `wlan0`.

### Linux raw-socket capture

```bash
sudo python3 ethernet_monitor.py --mode live --iface eth0 --count 30
```

This mode uses Linux `AF_PACKET` and is not supported on Windows or macOS by this implementation.

## GUI Controls

- **Mode:** Select Simulation or Live capture (Scapy).
- **Error rate:** Probability of injecting one random bit error into a simulated frame; `0.2` means 20%.
- **Interface:** Interface name for Scapy live capture.
- **MAC filter:** Display frames whose source or destination MAC address matches the entered text.
- **Type:** Filter by IPv4, ARP, IPv6, or LLDP.
- **Start / Stop:** Start or stop generation/capture.
- **Clear:** Clear displayed records and statistics.
- **Export CSV:** Save decoded frame records to CSV.
- **Export PCAP:** Save raw frame records to PCAP for tools such as Wireshark.

The GUI simulation runs continuously until **Stop** is pressed. It initializes a pool of six simulated MAC addresses.

## Understanding the Output

| Field | Description |
|---|---|
| `#` | Frame sequence number |
| `Time` | Time the frame was parsed |
| `Destination` | Destination MAC address |
| `Source` | Source MAC address |
| `Type` | Decoded EtherType/protocol |
| `VLAN` | VLAN ID, or `-` when no VLAN tag is present |
| `Len` | Raw frame length received by the application |
| `Payload` | Parsed payload length |
| `FCS rx` | Received FCS, when available |
| `FCS calc` | Recalculated CRC-32, when available |
| `Status` | `OK`, `CRC ERROR`, `WARN`, `RUNT`, or `N/A` |
| `Detail` | Additional IPv4 or ARP information when decoded |

## CRC-32 and Live Capture Notes

- Simulation mode builds the FCS and can intentionally corrupt a bit to demonstrate a CRC mismatch.
- Most network interface cards remove the FCS before delivering packets to capture software. Live captures therefore commonly show FCS status as `N/A`.
- CRC is an error-detection mechanism, not a security or authentication mechanism.
- Simulated frames are not transmitted onto the physical network.

## Testing Suggestions

1. **No injected errors:** Use `--error-rate 0` and check that simulated frames normally show `OK`.
2. **Error detection:** Use `--error-rate 0.5` and look for `CRC ERROR`.
3. **ARP filtering:** Use `--filter-type ARP`.
4. **CSV export:** Open the exported CSV in a spreadsheet application.
5. **PCAP export:** Open the exported PCAP in Wireshark.
6. **Hex view:** Select a row in the GUI to view the frame's hexadecimal bytes.

Example:

```bash
python ethernet_monitor.py --mode sim --count 100 --error-rate 0.1 --csv frames.csv --pcap capture.pcap
```

## Limitations

- Live captures commonly omit the FCS, so CRC verification is mainly demonstrated in simulation mode.
- Detailed payload decoding is implemented for IPv4 and ARP; IPv6 and LLDP payloads are not fully decoded.
- Linux `live` mode uses `AF_PACKET`; Scapy is the cross-platform capture option.
- Live capture depends on permissions, drivers, interface names, and packet-capture support.
- Simulated PCAP files include the generated FCS bytes; Wireshark may display them as part of the frame.

## Technologies Used

Python · Tkinter · Scapy (optional) · CRC-32/FCS · Ethernet II · IEEE 802.1Q VLAN · CSV · PCAP · Wireshark

## Author

**Muhammed Kaif B**  
Roll No: 48  
Class: S5 B2

## License

No license has been specified. Add a `LICENSE` file if you intend to distribute this project under a particular open-source license.
