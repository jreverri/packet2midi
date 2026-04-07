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
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import mido

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

    def send_note(self, note, velocity=64):
        msg = mido.Message('note_on', note=min(127, max(0, note)), velocity=min(127, max(0, velocity)))
        self.outport.send(msg)

    def send_cc(self, control, value):
        msg = mido.Message('control_change', control=control, value=min(127, max(0, value)))
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

    def get_velocity(self, layer_config, packet_size):
        v_source = layer_config.get('velocity_source', 'size')
        if v_source == 'fixed':
            return layer_config.get('fixed_velocity', 64)
        return min(127, int((packet_size / 1500) * 127))

    def process_cc_mappings(self, cc_config, packet):
        if not cc_config:
            return
        
        # Calculate context values
        size_val = min(127, int((len(packet) / 1500) * 127))
        entropy_val = 0
        if packet.haslayer(Raw):
            entropy_val = sum(packet[Raw].load) % 128

        for cc_num, source in cc_config.items():
            if source == 'size':
                self.midi.send_cc(int(cc_num), size_val)
            elif source == 'entropy':
                self.midi.send_cc(int(cc_num), entropy_val)

    def process(self, packet):
        self.packet_count += 1
        mappings = self.profile.get('mappings', {})

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            last_octet = int(src_ip.split('.')[-1])
            base_note = self.quantizer.get_note(last_octet)
            packet_size = len(packet)

            # Determine Layer Configuration
            layer_cfg = None
            if packet.haslayer(TCP):
                layer_cfg = mappings.get('tcp')
            elif packet.haslayer(UDP):
                layer_cfg = mappings.get('udp')
            elif packet.haslayer(ICMP):
                layer_cfg = mappings.get('icmp')

            if layer_cfg:
                # Handle Fixed Note (e.g. ICMP Kick)
                if 'fixed_note' in layer_cfg:
                    note = layer_cfg['fixed_note']
                else:
                    note = base_note + layer_cfg.get('note_offset', 0)
                
                velocity = self.get_velocity(layer_cfg, packet_size)
                self.midi.send_note(note, velocity=velocity)
                
                # Handle CC Mappings
                self.process_cc_mappings(layer_cfg.get('cc'), packet)

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
        
    with open(args.profile, 'r') as f:
        profile = yaml.safe_load(f)

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
