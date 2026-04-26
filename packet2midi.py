#!/usr/bin/env python3
"""
Packet2Midi: Turn your network telemetry into a Rhythmic Industrial Soundscape.
Supports dynamic YAML Mapping Profiles.
"""

import argparse
import collections
import math
import queue
import sys
import time
import threading
import yaml
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
import mido

# Explicitly set the mido backend to rtmidi
try:
    mido.set_backend('mido.backends.rtmidi')
except Exception as e:
    print(f"[!] Warning: Could not set mido backend to rtmidi. Using default. Error: {e}")

def byte_entropy(data):
    """Shannon entropy of a byte sequence, returns 0.0–8.0 bits."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

def entropy_to_midi(entropy):
    """Map 0.0–8.0 bits of entropy to MIDI range 0–127."""
    return min(127, int((entropy / 8.0) * 127))

class Quantizer:
    """Forces raw 0-255 values into a specific musical scale."""
    def __init__(self, scale):
        self.scale = scale if scale else list(range(12, 127))
    
    def get_note(self, raw_val):
        index = int((raw_val / 255) * (len(self.scale) - 1))
        return self.scale[index]

class MidiEngine:
    """Handles MIDI message dispatching and panic resets."""
    def __init__(self, port_name=None, virtual=True):
        try:
            if virtual:
                self.outport = mido.open_output('Packet2Midi_Out', virtual=True)
            else:
                self.outport = mido.open_output(port_name)
            print(f"[*] MIDI Engine Initialized: {self.outport.name}")
        except Exception as e:
            print(f"[!] MIDI Error: {e}")
            sys.exit(1)

        # Single background thread drains the note-off queue instead of spawning
        # one thread per note, which accumulates under high-traffic loads.
        self._note_off_queue = queue.PriorityQueue()
        self._worker = threading.Thread(target=self._note_off_worker, daemon=True)
        self._worker.start()

    def _note_off_worker(self):
        while True:
            fire_at, note = self._note_off_queue.get()
            delay = fire_at - time.time()
            if delay > 0:
                time.sleep(delay)
            self.outport.send(mido.Message('note_off', note=note, velocity=0))

    def send_note(self, note, velocity=64, duration=0.1):
        safe_note = min(127, max(0, int(note)))
        safe_velocity = min(127, max(0, int(velocity)))
        self.outport.send(mido.Message('note_on', note=safe_note, velocity=safe_velocity))
        self._note_off_queue.put((time.time() + duration, safe_note))

    def send_cc(self, control, value):
        msg = mido.Message('control_change', control=min(127, max(0, int(control))), value=min(127, max(0, int(value))))
        self.outport.send(msg)

    def panic(self):
        print("[!] PANIC: Resetting all MIDI channels...")
        for channel in range(16):
            self.outport.send(mido.Message('control_change', control=123, value=0, channel=channel))

class PacketProcessor:
    """The brain: Maps network telemetry to MIDI events based on a YAML profile."""
    def __init__(self, midi_engine, profile, verbose=False):
        self.midi = midi_engine
        self.profile = profile
        self.verbose = verbose
        self.quantizer = Quantizer(profile.get('scale'))
        self.packet_count = 0
        self.last_note_time = 0
        self._lock = threading.Lock()
        
        # Configuration settings with sensible defaults
        self.settings = profile.get('settings', {})
        self.max_mtu = self.settings.get('max_mtu', 1500)
        self.min_interval = self.settings.get('min_interval', 0.05) # Rate limit (50ms)
        self.note_duration = self.settings.get('note_duration', 0.1)

    def get_velocity(self, layer_config, packet_size):
        v_source = layer_config.get('velocity_source', 'size')
        if v_source == 'fixed':
            return layer_config.get('fixed_velocity', 64)
        # Scale packet size to MIDI velocity (0-127) based on max_mtu
        return min(127, int((packet_size / self.max_mtu) * 127))

    def process_cc_mappings(self, cc_config, packet):
        if not cc_config:
            return
        
        # Calculate context values
        size_val = min(127, int((len(packet) / self.max_mtu) * 127))
        entropy_val = 0
        if packet.haslayer(Raw):
            entropy_val = entropy_to_midi(byte_entropy(packet[Raw].load))

        for cc_num, source in cc_config.items():
            if source == 'size':
                self.midi.send_cc(int(cc_num), size_val)
            elif source == 'entropy':
                self.midi.send_cc(int(cc_num), entropy_val)

    def process(self, packet):
        self.packet_count += 1
        
        if self.verbose:
            print(f"[{self.packet_count}] {packet.summary()}")
        
        # Rate Limiting: Avoid MIDI congestion on high-traffic networks
        current_time = time.time()
        with self._lock:
            if current_time - self.last_note_time < self.min_interval:
                return
            self.last_note_time = current_time
            
        mappings = self.profile.get('mappings', {})
        packet_size = len(packet)

        # 1. Calculate Payload Entropy (The "Chaos" value)
        entropy_val = 0
        is_high_entropy = False
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            e = byte_entropy(payload)
            entropy_val = entropy_to_midi(e)
            is_high_entropy = e > 7.0  # > 7.0 bits indicates encrypted/compressed data

        # 2. Determine Note/Pitch identity
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            last_octet = int(src_ip.split('.')[-1])
            base_note = self.quantizer.get_note(last_octet)
        elif packet.haslayer(Ether):
            last_byte = int(packet[Ether].src.split(':')[-1], 16)
            base_note = self.quantizer.get_note(last_byte)
        else:
            base_note = self.quantizer.get_note(0)

        # 3. Determine Layer Configuration
        layer_cfg = None
        
        # High-Entropy Alert (Overrides standard mapping if defined)
        if is_high_entropy and 'high_entropy' in mappings:
            layer_cfg = mappings.get('high_entropy')
        
        # Protocol Specifics
        elif packet.haslayer(TCP):
            layer_cfg = mappings.get('tcp')
            # Check for specific flags (SYN/RST/FIN) if defined in profile
            flags = str(packet[TCP].flags)
            if 'S' in flags and 'tcp_syn' in mappings:
                layer_cfg = mappings.get('tcp_syn')
            elif 'R' in flags and 'tcp_rst' in mappings:
                layer_cfg = mappings.get('tcp_rst')
                
        elif packet.haslayer(UDP):
            layer_cfg = mappings.get('udp')
        elif packet.haslayer(ICMP):
            layer_cfg = mappings.get('icmp')
            
        # Fallback to default mapping if defined
        if not layer_cfg:
            layer_cfg = mappings.get('default')

        if layer_cfg:
            # Handle Fixed Note (e.g. ICMP Kick)
            if 'fixed_note' in layer_cfg:
                note = layer_cfg['fixed_note']
            else:
                note = base_note + layer_cfg.get('note_offset', 0)
            
            velocity = self.get_velocity(layer_cfg, packet_size)
            duration = layer_cfg.get('duration', self.note_duration)
            
            self.midi.send_note(note, velocity=velocity, duration=duration)
            
            # Handle CC Mappings
            self.process_cc_mappings(layer_cfg.get('cc'), packet)

def validate_profile(profile):
    """Ensures the profile has the minimum required structure."""
    if not isinstance(profile, dict):
        return False, "Profile must be a YAML dictionary."
    if 'mappings' not in profile:
        return False, "Profile missing 'mappings' section."
    max_mtu = profile.get('settings', {}).get('max_mtu', 1500)
    if max_mtu <= 0:
        return False, "'max_mtu' must be greater than 0."
    return True, None

def main():
    parser = argparse.ArgumentParser(
        description="Packet2Midi: Turn network telemetry into a Rhythmic Industrial Soundscape.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example Usage:
  python3 packet2midi.py -i eth0 -p profiles/industrial.yaml --virtual
  python3 packet2midi.py -i wlan1mon -p profiles/ids_alerts.yaml --verbose
  python3 packet2midi.py -P capture.pcap -p profiles/malware_detonation.yaml --virtual
  python3 packet2midi.py -i eth0 -p profiles/ids_alerts.yaml -f "not port 22"

Profile variables (defined in YAML):
  scale: List of MIDI note integers (e.g. [36, 39, 41...])
  settings:
    max_mtu: Max packet size for velocity scaling (default: 1500)
    min_interval: Min time between MIDI notes in seconds (default: 0.05)
    note_duration: Global length of MIDI notes (default: 0.1)
  mappings:
    tcp, udp, icmp, tcp_syn, tcp_rst, high_entropy, default
        """
    )
    parser.add_argument("-i", "--iface", default="eth0", help="Network interface to sniff (default: eth0)")
    parser.add_argument("-P", "--pcap", default=None, help="Replay a PCAP file instead of live capture")
    parser.add_argument("-f", "--filter", default=None, help="BPF filter string (e.g. 'not port 22')")
    parser.add_argument("-p", "--profile", required=True, help="Path to the YAML mapping profile (e.g. profiles/industrial.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display real-time packet summaries (tcpdump-style)")
    parser.add_argument("-m", "--virtual", action="store_true", help="Enable virtual MIDI output port (Packet2Midi_Out)")
    
    args = parser.parse_args()

    # Load Profile
    if not os.path.exists(args.profile):
        print(f"[!] Profile not found: {args.profile}")
        sys.exit(1)
        
    try:
        with open(args.profile, 'r') as f:
            profile = yaml.safe_load(f)
    except Exception as e:
        print(f"[!] Error parsing YAML profile: {e}")
        sys.exit(1)

    # Validate Profile
    is_valid, error_msg = validate_profile(profile)
    if not is_valid:
        print(f"[!] Invalid Profile: {error_msg}")
        sys.exit(1)

    # Initialize Engine
    midi = MidiEngine(virtual=args.virtual)
    processor = PacketProcessor(midi, profile, verbose=args.verbose)

    if args.pcap:
        print(f"[*] Replaying PCAP: {args.pcap}")
    else:
        print(f"[*] Starting Packet2Midi on {args.iface}...")
    if args.filter:
        print(f"[*] BPF Filter: {args.filter}")
    print(f"[*] Loaded Profile: {profile.get('name', 'Unnamed')}")
    print("[*] Press Ctrl+C to stop.")

    try:
        if args.pcap:
            if not os.path.exists(args.pcap):
                print(f"[!] PCAP file not found: {args.pcap}")
                sys.exit(1)
            sniff(offline=args.pcap, prn=processor.process, store=0, filter=args.filter)
        else:
            sniff(iface=args.iface, prn=processor.process, store=0, filter=args.filter)
    except KeyboardInterrupt:
        midi.panic()
        print("\n[*] Shutting down. Frequency silence returned.")
    except Exception as e:
        print(f"[!] Error: {e}")
        midi.panic()

if __name__ == "__main__":
    main()
