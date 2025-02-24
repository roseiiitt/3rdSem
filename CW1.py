import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import scapy.all as scapy
import threading
import queue
from abc import ABC, abstractmethod
import re


# Abstract Base Class for Packet Processing
class PacketProcessor(ABC):
    @abstractmethod
    def process_packet(self, packet):
        pass


# Concrete Implementation of PacketProcessor
class DefaultPacketProcessor(PacketProcessor):
    def process_packet(self, packet):
        details = f"Time: {packet.time} | Length: {len(packet)} bytes\n"
        
        # Process IP Layer
        if packet.haslayer(scapy.IP):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
            details += f"Source: {src} -> Destination: {dst} | Protocol: {proto}\n"
        
        # Process HTTP Requests and Show Sensitive Info (without masking)
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            raw_data = str(packet[scapy.Raw].load)
            details += self.show_sensitive_data(raw_data)

        details += f"Packet Summary: {packet.summary()}\n\n"
        return details

    def show_sensitive_data(self, raw_data):
        # Just return raw_data as is without masking
        return f"Data: {raw_data}\n"


# PacketSniffer Class (Encapsulates Sniffing Logic)
class PacketSniffer:
    def __init__(self, packet_processor: PacketProcessor):
        self.sniffing = False
        self.interface = "eth0"
        self.filter = ""
        self.packets = []  # Store packets here
        self.sniff_thread = None
        self.packet_queue = queue.Queue()
        self.packet_processor = packet_processor  # Dependency Injection

    def sniff_packets(self):
        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.filter,  # Apply the filter passed from GUI
                prn=self.process_packet_for_gui,
                store=False,  # Don't store the packets automatically
                stop_filter=lambda p: not self.sniffing,
            )
        except Exception as e:
            self.packet_queue.put(f"Error: {str(e)}\n")

    def process_packet_for_gui(self, packet):
        # Store packet in the list
        self.packets.append(packet)  
        details = self.packet_processor.process_packet(packet)
        self.packet_queue.put(details)

    def start_sniffing(self, interface, packet_filter):
        self.sniffing = True
        self.interface = interface
        self.filter = packet_filter  # Apply the filter
        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        if self.sniff_thread:
            self.sniff_thread.join(timeout=1)

    def save_pcap(self, filename):
        # Save the packets stored in self.packets to a PCAP file
        if self.packets:
            scapy.wrpcap(filename, self.packets)
        else:
            messagebox.showwarning("Warning", "No packets to save.")

    def load_pcap(self, filename):
        try:
            self.packets = scapy.rdpcap(filename)
            return [self.packet_processor.process_packet(pkt) for pkt in self.packets]
        except Exception as e:
            return [f"Error loading PCAP: {str(e)}"]


# SnifferApp Class (Encapsulates GUI Logic)
class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("700x550")
        self.root.configure(bg="#2C3E50")

        self.text_area = scrolledtext.ScrolledText(root, width=90, height=20, bg="black", fg="green")
        self.text_area.pack(pady=10)

        self.create_widgets()
        self.sniffer = PacketSniffer(DefaultPacketProcessor())  # Injecting Dependency

        # Start a thread to read from the queue and update the GUI
        self.update_thread = threading.Thread(target=self.update_gui_from_queue, daemon=True)
        self.update_thread.start()

    def create_widgets(self):
        frame = tk.Frame(self.root, bg="#2C3E50")
        frame.pack(pady=10)

        tk.Label(frame, text="Interface:", bg="#2C3E50", fg="white").grid(row=0, column=0, padx=5)
        self.interface_entry = tk.Entry(frame, width=15)
        self.interface_entry.grid(row=0, column=1, padx=5)

        tk.Label(frame, text="Filter:", bg="#2C3E50", fg="white").grid(row=0, column=2, padx=5)
        self.filter_entry = tk.Entry(frame, width=40)  # Updated width for complex filters
        self.filter_entry.grid(row=0, column=3, padx=5)

        btn_frame = tk.Frame(self.root, bg="#2C3E50")
        btn_frame.pack(pady=10)

        self.create_button(btn_frame, "Start Sniffing", self.start_sniffing, "red").grid(row=0, column=0, padx=5)
        self.create_button(btn_frame, "Stop Sniffing", self.stop_sniffing, "red").grid(row=0, column=1, padx=5)
        self.create_button(btn_frame, "Save to PCAP", self.save_pcap, "red").grid(row=0, column=2, padx=5)
        self.create_button(btn_frame, "Load PCAP", self.load_pcap, "red").grid(row=0, column=3, padx=5)
        self.create_button(btn_frame, "Clear Output", self.clear_output, "red").grid(row=0, column=4, padx=5)

    def create_button(self, parent, text, command, color):
        return tk.Button(parent, text=text, command=command, bg="#2C3E50", fg="black", width=15, height=2, font=("Arial", 10, "bold"))

    def update_text(self, text):
        self.text_area.insert(tk.END, text)
        self.text_area.yview(tk.END)

    def update_gui_from_queue(self):
        while True:
            try:
                packet_details = self.sniffer.packet_queue.get()
                if packet_details:
                    self.update_text(packet_details)
            except Exception as e:
                pass  # Handle potential errors silently

    def clear_output(self):
        self.text_area.delete(1.0, tk.END)

    def start_sniffing(self):
        interface = self.interface_entry.get()
        packet_filter = self.filter_entry.get()
        if not interface:
            messagebox.showerror("Error", "Please enter a network interface!")
            return
        try:
            self.sniffer.start_sniffing(interface, packet_filter)
            self.update_text(f"Started sniffing on {interface} with filter '{packet_filter}'...\n")
        except Exception as e:
            messagebox.showerror("Error", f"Error starting sniffing: {str(e)}")

    def stop_sniffing(self):
        self.sniffer.stop_sniffing()
        self.update_text("\nSniffing Stopped.\n")

    def save_pcap(self):
        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
        if filename:
            try:
                self.sniffer.save_pcap(filename)
                messagebox.showinfo("Success", "Packets saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving PCAP file: {str(e)}")

    def load_pcap(self):
        filename = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
        if filename:
            packets = self.sniffer.load_pcap(filename)
            self.text_area.insert(tk.END, "\nLoaded Packets:\n" + "".join(packets))
            messagebox.showinfo("Success", "PCAP file loaded successfully!")


# Main Execution
if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()
