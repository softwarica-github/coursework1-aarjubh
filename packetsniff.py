import tkinter as tk
from scapy.all import sniff, Ether
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root

        self.root.configure(bg="black")
        self.root.title("Packet Sniffer")

        self.output_text = tk.Text(self.root, height=20, width=70, borderwidth=5)
        self.output_text.pack()
        self.output_text.configure(bg="#B2B2CF")  

        self.start_button = tk.Button(self.root, text="Start Sniffing", font=('Courier', 15, 'bold'), command=self.start_sniffing, borderwidth=5)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(self.root, text="Stop Sniffing", font=('Courier', 15, 'bold'), command=self.stop_sniffing, borderwidth=5)
        self.stop_button.pack(pady=10)

        self.clear_button = tk.Button(self.root, text="Clear Output", font=('Courier', 15, 'bold'), command=self.clear_output, borderwidth=5)
        self.clear_button.pack(pady=10)

        self.sort_button = tk.Button(self.root, text="Sort Logs", font=('Courier', 15, 'bold'), command=self.sort_logs, borderwidth=5)
        self.sort_button.pack(pady=10)

        self.save_button = tk.Button(self.root, text="Save Logs", font=('Courier', 15, 'bold'), command=self.save_logs_to_file, borderwidth=5)
        self.save_button.pack(pady=10)

        self.status_label = tk.Label(self.root, text="")
        self.status_label.pack()

        self.sniffing = False
        self.packet_count = 0
        self.sniff_thread = None
        self.sniffer = None

    def packet_handler(self, packet):
        if self.sniffing:
            if packet.haslayer('IP'):
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                self.output_text.insert(tk.END, f"Source IP: {src_ip} --> Destination IP: {dst_ip}\n")

                if packet.haslayer('TCP'):
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                    self.output_text.insert(tk.END, f"Source Port: {src_port} --> Destination Port: {dst_port}\n")

                if packet.haslayer(Ether):
                    src_mac = packet[Ether].src
                    dst_mac = packet[Ether].dst
                    self.output_text.insert(tk.END, f"Source MAC: {src_mac} --> Destination MAC: {dst_mac}\n")

            self.packet_count += 1
            self.status_label.config(text=f"Sniffed {self.packet_count} packets")

            self.output_text.insert(tk.END, "\n")
            self.output_text.see(tk.END)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.packet_count = 0
            self.status_label.config(text="Sniffing in progress...")
            self.output_text.delete("1.0", tk.END)
            self.sniff_thread = threading.Thread(target=self.start_sniff_thread)
            self.sniff_thread.start()

    def start_sniff_thread(self):
        self.sniffer = sniff(filter="ip", prn=self.packet_handler, count=0)

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            if self.sniffer:
                self.sniffer._stop()
            self.packet_count = 0
            self.status_label.config(text="Sniffing stopped")

    def clear_output(self):
        self.output_text.delete("1.0", tk.END)
        self.status_label.config(text="Output cleared")
        self.packet_count = 0

    def save_logs(self, filename):
        with open(filename, 'w') as file:
            file.write(self.output_text.get("1.0", tk.END))

    def merge_sort(self, data):
        if len(data) <= 1:
            return data

        middle = len(data) // 2
        left_half = data[:middle]
        right_half = data[middle:]

        left_half = self.merge_sort(left_half)
        right_half = self.merge_sort(right_half)

        return self.merge(left_half, right_half)

    def merge(self, left, right):
        result = []
        left_idx, right_idx = 0, 0

        while left_idx < len(left) and right_idx < len(right):
            if left[left_idx] < right[right_idx]:
                result.append(left[left_idx])
                left_idx += 1
            else:
                result.append(right[right_idx])
                right_idx += 1

        result.extend(left[left_idx:])
        result.extend(right[right_idx:])
        return result

    '''def sort_logs(self):
        current_logs = self.output_text.get("1.0", tk.END).splitlines()
        sorted_logs = self.merge_sort(current_logs)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "\n".join(sorted_logs))
        self.status_label.config(text="Logs sorted")'''
    def sort_logs(self):
        current_logs = self.output_text.get("1.0", tk.END).splitlines()
        sorted_logs = self.merge_sort(current_logs)
        
        print("Sorted Logs:")
        for log in sorted_logs:
            print(log)
        
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "\n".join(sorted_logs))
        self.status_label.config(text="Logs sorted")

    def save_logs_to_file(self):
        filename = "packet_logs.txt"  
        self.save_logs(filename)
        self.status_label.config(text=f"Logs saved to {filename}")

def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()