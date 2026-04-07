#!/usr/bin/env python3
"""
Packet2Midi: Turn your network telemetry into a Rhythmic Industrial Soundscape.
Supports dynamic YAML Mapping Profiles.
"""

import argparse
import sys
import time
import yaml
import os
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
import mido

# Explicitly set the mido backend to rtmidi
try:
    mido.set_backend('mido.backends.rtmidi')
except Exception as e:
    print(f"[!] Warning: Could not set mido backend to rtmidi. Using default. Error: {e}")

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

    def send_note(self, note, velocity=64, duration=0.1):
        """Sends a note_on message followed by a note_off after 'duration' seconds."""
        # Ensure values are within MIDI range
        safe_note = min(127, max(0, int(note)))
        safe_velocity = min(127, max(0, int(velocity)))
        
        # Send Note On
        msg_on = mido.Message('note_on', note=safe_note, velocity=safe_velocity)
        self.outport.send(msg_on)
        
        # Schedule Note Off
        def send_off():
            msg_off = mido.Message('note_off', note=safe_note, velocity=0)
            self.outport.send(msg_off)
            
        threading.Timer(duration, send_off).start()

    def send_cc(self, control, value):
        msg = mido.Message('control_change', control=min(127, max(0, int(control))), value=min(127, max(0, int(value))))
        self.outport.send(msg)

    def panic(self):
        print("[!] PANIC: Resetting all MIDI channels...")
        for channel in range(16):
            self.outport.send(mido.Message('control_change', control=123, value=0, channel=channel))

class PacketProcessor:
    """The brain: Maps network telemetry to MIDI events based on a YAML profile."""
    def __init__(self, midi_engine, profile):
        self.midi = midi_engine
        self.profile = profile
        self.quantizer = Quantizer(profile.get('scale'))
        self.packet_count = 0
        self.last_note_time = 0
        
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
            # Very basic entropy estimation
            entropy_val = sum(packet[Raw].load) % 128

        for cc_num, source in cc_config.items():
            if source == 'size':
                self.midi.send_cc(int(cc_num), size_val)
            elif source == 'entropy':
                self.midi.send_cc(int(cc_num), entropy_val)

    def process(self, packet):
        self.packet_count += 1
        
        # Rate Limiting: Avoid MIDI congestion on high-traffic networks
        current_time = time.time()
        if current_time - self.last_note_time < self.min_interval:
            return
            
        mappings = self.profile.get('mappings', {})
        packet_size = len(packet)

        # 1. Determine Note/Pitch identity
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            last_octet = int(src_ip.split('.')[-1])
            base_note = self.quantizer.get_note(last_octet)
        elif packet.haslayer(Ether):
            # Fallback for non-IP traffic: use MAC address last byte
            last_byte = int(packet[Ether].src.split(':')[-1], 16)
            base_note = self.quantizer.get_note(last_byte)
        else:
            base_note = self.quantizer.get_note(0)

        # 2. Determine Layer Configuration
        layer_cfg = None
        if packet.haslayer(TCP):
            layer_cfg = mappings.get('tcp')
        elif packet.haslayer(UDP):
            layer_cfg = mappings.get('udp')
        elif packet.haslayer(ICMP):
            layer_cfg = mappings.get('icmp')
            
        # Fallback to default mapping if defined
        if not layer_cfg:
            layer_cfg = mappings.get('default')

        if layer_cfg:
            self.last_note_time = current_time
            
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
    return True, None

def main():
    parser = argparse.ArgumentParser(description="Packet2Midi: Network Sonification Engine")
    parser.add_argument("-i", "--iface", default="eth0", help="Network interface to sniff")
    parser.add_argument("-p", "--profile", required=True, help="Path to YAML mapping profile")
    parser.add_argument("-v", "--virtual", action="store_true", help="Use virtual MIDI port")
    
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
    processor = PacketProcessor(midi, profile)

    print(f"[*] Starting Packet2Midi on {args.iface}...")
    print(f"[*] Loaded Profile: {profile.get('name', 'Unnamed')}")
    print("[*] Press Ctrl+C to stop.")

    try:
        sniff(iface=args.iface, prn=processor.process, store=0)
    except KeyboardInterrupt:
        midi.panic()
        print("\n[*] Shutting down. Frequency silence returned.")
    except Exception as e:
        print(f"[!] Error: {e}")
        midi.panic()

if __name__ == "__main__":
    main()
