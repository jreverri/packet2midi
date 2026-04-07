# Packet2Midi 🎹📡

![Packet2Midi Header](images/packet2midi.png)

**Turn your network telemetry into a Rhythmic Industrial Soundscape.**

`Packet2Midi` is an open-source framework designed for network sonification. It bridges the gap between the digital wire and analog synthesis by converting real-time network traffic (IP headers, packet sizes, protocol types) into MIDI CC and Note data for modular synthesizers.

Whether you're a creative coder, a modular synth enthusiast, or a security researcher, `Packet2Midi` allows you to *hear* the heartbeat of your network.

---

## 🚀 Key Features

- **Real-time Sniffing:** Powered by `Scapy` for high-performance packet capture.
- **Dynamic Mapping Profiles:** Load YAML-based profiles to change scales, CC mappings, and protocol behaviors instantly.
- **Musical Quantization:** Force raw network data into user-defined musical scales (e.g., C-Minor Pentatonic) defined in your profile.
- **Auditory IDS:** Custom mapping for security events:
    - **ICMP Pings:** Mapped to low-frequency thuds (Kick Drums).
    - **TCP/UDP:** Differentiated voices (Leads vs. Sub-bass).
    - **Payload Entropy:** Map chaotic payload data to "Chaos" CC parameters.
- **Remote Sensing:** Support for piped traffic from remote sensors or local USB WiFi interfaces in monitor mode (802.11).

---

## 🛠 Hardware & Setup Options

### Option 1: The Physical Rack (Hardware)
- **Brain:** Raspberry Pi 4 or 5 (running Raspberry Pi OS Lite).
- **Interface:** USB WiFi interface with Monitor Mode support (e.g., Alfa AWUS036ACM).
- **MIDI-to-CV:** A module to bridge the Pi to your rack (e.g., Expert Sleepers ES-8/9, ALM mmMidi, or Hexinverter Mutant Brain).
- **Synth:** A physical Eurorack or modular system.

### Option 2: The Virtual Rack (VCV Rack)
If you don't have a physical modular synth, you can use **VCV Rack** (Free/Pro) on your laptop.
- **Brain:** Raspberry Pi 4 or 5.
- **Interface:** USB WiFi interface with Monitor Mode support (e.g., Alfa AWUS036ACM).
- **Connection:** 
    - **USB-to-USB MIDI:** Use a standard USB MIDI interface cable to connect the Pi to your computer.
    - **Virtual MIDI (Network):** Use `rtpMIDI` (Windows) or built-in Network MIDI (macOS) to send MIDI data over your local WiFi/Ethernet from the Pi to VCV Rack.
- **VCV Rack Setup:** Use the `MIDI-to-CV` module in VCV Rack and select the incoming MIDI port from your Pi.

---

## 📥 Installation

Follow these steps to get `Packet2Midi` running on your system.

### 1. Install System Dependencies
Install the required system libraries and tools:

```bash
sudo apt-get update
sudo apt-get install git libportmidi-dev python3-scapy python3-mido python3-rtmidi python3-yaml vim aircrack-ng
```

### 2. Clone the Repository
Open your terminal and clone the project from GitHub:

```bash
git clone https://github.com/jreverri/packet2midi.git
cd packet2midi
```

### 3. Setup Python Virtual Environment
Create and activate a virtual environment to manage dependencies safely:

```bash
# Create the virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

*Note: You must run `source venv/bin/activate` every time you open a new terminal to use the tool.*

---

## 🔒 Security & Permissions (Highly Recommended)

By default, sniffing network traffic requires root privileges (`sudo`). However, running a Python script as `root` is a security risk. You can allow your Python virtual environment to sniff traffic without `sudo` by granting it the necessary capabilities:

```bash
# Grant network sniffing capabilities to the Python binary in your venv
sudo setcap cap_net_raw,cap_net_admin=eip venv/bin/python3
```

After running this, you can start the script normally:
`python3 packet2midi.py --iface eth0 --profile profiles/industrial.yaml`

---

## 🎹 Mapping Profiles

`Packet2Midi` uses YAML profiles to define how network data is translated into sound. Profiles are located in the `profiles/` directory.

### Current Profiles:
- **`industrial.yaml`**: Gritty, minor-scale textures with heavy CC modulation for a rhythmic industrial vibe.
- **`ambient.yaml`**: Soft, Aeolian scales with fixed low velocities and slow filter sweeps.
- **`ids_alerts.yaml`**: Tense, alert-focused mappings with sub-bass ICMP warnings for monitoring security events.

---

## 📖 Usage

### Basic Usage with a Profile
```bash
sudo python3 packet2midi.py --iface eth0 --profile profiles/industrial.yaml --virtual
```

### Monitor Mode (Sonifying the Air)
```bash
sudo airmon-ng start wlan1
sudo python3 packet2midi.py --iface wlan1mon --profile profiles/ids_alerts.yaml
```

### Remote Pipe (WiFi Pineapple)
```bash
ssh root@172.16.42.1 'tcpdump -i wlan1 -U -w -' | sudo python3 packet2midi.py --profile profiles/ambient.yaml
```

---

## 🎨 Creative Intent

`Packet2Midi` was born from the "Hacker Tax"—the idea of contributing creative tools back to the community. It was showcased at **DEF CON Singapore** and has been submitted for consideration at **HOPE 26** as a way to explore the aesthetic and diagnostic potential of our digital environments.

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

*"Beep Boop Beep – Auralizing your Network with Python and Synthesizers"*
