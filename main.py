import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
from scapy.all import ARP, Ether, srp
import ipaddress

COMMON_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAP SSL", 995: "POP3 SSL", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP Proxy"
}

class NetworkToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Local Network Scanner & Port Tool")
        self.root.geometry("900x600")
        self.root.resizable(False, False)

        style = ttk.Style()
        style.theme_use('clam')

        self.target_ip = tk.StringVar()
        self.scan_protocol = tk.StringVar(value="TCP")
        self.status_var = tk.StringVar(value="Ready")
        
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.LabelFrame(main_frame, text=" Network Devices ", padding="10")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        btn_refresh = ttk.Button(left_frame, text="Scan Network for Devices", command=self.start_device_scan)
        btn_refresh.pack(pady=(0, 10), fill=tk.X)

        columns = ("ip", "mac")
        self.tree = ttk.Treeview(left_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        self.tree.column("ip", width=120)
        self.tree.column("mac", width=150)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree.bind('<<TreeviewSelect>>', self.on_device_select)

        right_frame = ttk.LabelFrame(main_frame, text=" Port Scanner ", padding="10")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill=tk.X, pady=5)
        ttk.Label(input_frame, text="Target IP:").pack(side=tk.LEFT)
        ttk.Entry(input_frame, textvariable=self.target_ip).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        range_frame = ttk.Frame(right_frame)
        range_frame.pack(fill=tk.X, pady=5)
        ttk.Label(range_frame, text="Ports:").pack(side=tk.LEFT)
        self.port_start = ttk.Entry(range_frame, width=8)
        self.port_start.insert(0, "1")
        self.port_start.pack(side=tk.LEFT, padx=2)
        ttk.Label(range_frame, text="-").pack(side=tk.LEFT)
        self.port_end = ttk.Entry(range_frame, width=8)
        self.port_end.insert(0, "1024")
        self.port_end.pack(side=tk.LEFT, padx=2)

        proto_frame = ttk.Frame(right_frame)
        proto_frame.pack(fill=tk.X, pady=10)
        ttk.Label(proto_frame, text="Protocol:").pack(side=tk.LEFT)
        ttk.Radiobutton(proto_frame, text="TCP", variable=self.scan_protocol, value="TCP").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(proto_frame, text="UDP (Slow/Unreliable)", variable=self.scan_protocol, value="UDP").pack(side=tk.LEFT)

        self.btn_scan = ttk.Button(right_frame, text="Start Port Scan", command=self.start_port_scan)
        self.btn_scan.pack(fill=tk.X, pady=5)

        self.progress = ttk.Progressbar(right_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)

        self.result_area = scrolledtext.ScrolledText(right_frame, height=15, state='disabled', font=("Consolas", 9))
        self.result_area.pack(fill=tk.BOTH, expand=True)

        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_device_scan(self):
        self.tree.delete(*self.tree.get_children())
        self.status_var.set("Scanning network for devices... Please wait.")
        threading.Thread(target=self.scan_network_thread, daemon=True).start()

    def scan_network_thread(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            target_subnet = ".".join(local_ip.split('.')[:3]) + ".1/24"

            arp = ARP(pdst=target_subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=2, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})

            self.root.after(0, self.update_device_list, devices)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Network Scan Failed:\n{e}"))
            self.root.after(0, lambda: self.status_var.set("Error during network scan."))

    def update_device_list(self, devices):
        for dev in devices:
            self.tree.insert("", tk.END, values=(dev['ip'], dev['mac']))
        self.status_var.set(f"Network scan complete. Found {len(devices)} devices.")

    def on_device_select(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            item = self.tree.item(selected_item)
            ip = item['values'][0]
            self.target_ip.set(ip)

    def start_port_scan(self):
        ip = self.target_ip.get()
        if not ip:
            messagebox.showwarning("Input Error", "Please select or enter an IP address.")
            return

        try:
            start_p = int(self.port_start.get())
            end_p = int(self.port_end.get())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be numbers.")
            return

        self.btn_scan.config(state='disabled')
        self.result_area.config(state='normal')
        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, f"Scanning {ip} ({self.scan_protocol.get()})...\n" + "-"*40 + "\n")
        self.result_area.config(state='disabled')
        
        threading.Thread(target=self.scan_ports_thread, args=(ip, start_p, end_p), daemon=True).start()

    def scan_ports_thread(self, ip, start_port, end_port):
        protocol = self.scan_protocol.get()
        total_ports = end_port - start_port + 1
        
        self.root.after(0, lambda: self.progress.configure(maximum=total_ports, value=0))

        for i, port in enumerate(range(start_port, end_port + 1)):
            is_open = False
            service_name = COMMON_PORTS.get(port, "Unknown")
            
            try:
                if protocol == "TCP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        is_open = True
                    sock.close()
                
                elif protocol == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1.0)
                    sock.sendto(b"test", (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024)
                        is_open = True 
                    except socket.timeout:
                        is_open = False
                        pass
                    except ConnectionResetError:
                        is_open = False
                    sock.close()

            except:
                pass

            if is_open:
                msg = f"[+] Port {port} \t[{service_name}]\t : OPEN\n"
                self.root.after(0, self.append_result, msg)
            
            self.root.after(0, lambda v=i+1: self.progress.configure(value=v))

        self.root.after(0, self.finish_scan)

    def append_result(self, text):
        self.result_area.config(state='normal')
        self.result_area.insert(tk.END, text)
        self.result_area.see(tk.END)
        self.result_area.config(state='disabled')

    def finish_scan(self):
        self.btn_scan.config(state='normal')
        self.status_var.set("Port scan completed.")
        self.append_result("\nScan Finished.")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolApp(root)
    root.mainloop()