# Packet2Midi 🎹📡

**Turn your network telemetry into a Rhythmic Industrial Soundscape.**

`Packet2Midi` is an open-source framework designed for network sonification. It bridges the gap between the digital wire and analog synthesis by converting real-time network traffic (IP headers, packet sizes, protocol types) into MIDI CC and Note data for modular synthesizers.

Whether you're a creative coder, a modular synth enthusiast, or a security researcher, `Packet2Midi` allows you to *hear* the heartbeat of your network.

---

## 🚀 Key Features

- **Real-time Sniffing:** Powered by `Scapy` for high-performance packet capture.
- **Musical Quantization:** Force raw network data into user-defined musical scales (e.g., C-Minor Pentatonic) to ensure your network always "performs" in key.
- **Auditory IDS:** A custom mapping engine for security events:
    - **ICMP Pings:** Low-frequency thuds.
    - **Nmap/SYN Scans:** High-speed, glitchy arpeggios.
    - **Honeypot Commands:** Map ASCII characters from attacker input directly to Control Voltage (CV).
- **Remote Sensing:** Support for piped traffic from remote sensors like the WiFi Pineapple or local USB WiFi interfaces in monitor mode (802.11).
- **Modular Mapping Profiles:** Easily swap between `industrial.py`, `ambient.py`, or `ids_alerts.py` to change the "voice" of your network.

---

## 🛠 Hardware Requirements

To get the most out of `Packet2Midi`, the following setup is recommended:

1.  **Brain:** Raspberry Pi 4 or 5 (running Raspberry Pi OS Lite).
2.  **Interface:** USB WiFi interface with Monitor Mode support (e.g., Alfa AWUS036ACM).
3.  **MIDI-to-CV:** A module to bridge the Pi to your rack (e.g., Expert Sleepers ES-8/9, ALM mmMidi, or Hexinverter Mutant Brain).
4.  **Synth:** A modular synthesizer (Eurorack, Buchla, etc.) to provide the "voice."

---

## 📥 Installation

### 1. System Dependencies
On your Raspberry Pi (or Linux machine), install the necessary libraries:

```bash
sudo apt-get update
sudo apt-get install libportmidi-dev python3-scapy python3-mido python3-rtmidi vim aircrack-ng
```

### 2. Python Environment
Install the Python requirements:

```bash
pip install scapy mido python-rtmidi
```

---

## 🎹 How it Works: The Mapping Philosophy

`Packet2Midi` translates the abstract data of a packet into musical parameters:

| Network Data | Musical Parameter | Result |
| :--- | :--- | :--- |
| **IP Source/Dest** | MIDI Note / Pitch | Specific hosts have their own "melody". |
| **Packet Size (MTU)** | Filter Cutoff / Resonance | Larger packets "open up" the sound. |
| **Protocol (TCP/UDP)** | Gate / Trigger | Rhythmic pulses based on traffic type. |
| **Entropy** | Modulation / Noise | High-entropy traffic creates chaotic textures. |
| **802.11 RSSI** | Velocity / Amplitude | Closer devices sound louder and more aggressive. |

---

## 📖 Usage

### Basic Local Sniffing
```bash
sudo python3 packet2midi.py --iface eth0 --profile industrial
```

### Monitor Mode (Sonifying the Air)
```bash
sudo airmon-ng start wlan1
sudo python3 packet2midi.py --iface wlan1mon --mode monitor
```

---

## 🎨 Creative Intent

`Packet2Midi` was born from the "Hacker Tax"—the idea of contributing creative tools back to the community. It was showcased at **DEF CON Singapore** and **HOPE 26** as a way to explore the aesthetic and diagnostic potential of our digital environments.

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

**Built with 🖤 by Jason Reverri.**
*"Beep Boop Beep – Auralizing your Network with Python and Synthesizers"*
