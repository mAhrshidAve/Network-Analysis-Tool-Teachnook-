import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP, UDP, wrpcap
from collections import Counter
import time
import tkinter as tk
from tkinter import messagebox, ttk
from threading import Thread
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import matplotlib.dates as mdates
from datetime import datetime
from tkinter import font as tkFont  # Import tkinter font module

captured_packets = []  # To store actual packets

# Data structure to store captured packet information
packet_data = {
    'Time': [],
    'Source IP': [],
    'Destination IP': [],
    'Protocol': [],
    'Packet Length': []
}

# Counter to track IP traffic, packets per second, and protocol distribution
ip_traffic = Counter()
protocol_distribution = Counter({"TCP": 0, "UDP": 0, "Other": 0})
packet_count_per_second = []

# Flag to control sniffing
sniffing = False

# Time for live graph (x-axis)
time_intervals = []

# Store potential issues and threats
detected_issues = []
detected_threats = []

# Thresholds for issue detection
THRESHOLD_IP_PACKET = 750  # Potential flood detection
THRESHOLD_PACKET_SIZE = 1500  # Unusually large packet size
THRESHOLD_PORT_SCANS = 10  # Potential port scan detection
THRESHOLD_UNUSUAL_CONNECTIONS = 5  # Threshold for unusual connections

# Function to detect issues and threats
def detect_issues(ip_src, pkt_len, ip_dst):
    # Detect IP flooding
    if ip_traffic[ip_src] > THRESHOLD_IP_PACKET:
        detected_issues.append(f"High traffic detected from {ip_src}!")
        detected_threats.append(f"Threat: IP flooding from {ip_src}")

    # Detect unusual packet sizes (large packets)
    if pkt_len > THRESHOLD_PACKET_SIZE:
        detected_issues.append(f"Large packet detected: {pkt_len} bytes from {ip_src}")
        detected_threats.append(f"Threat: Large packet size from {ip_src}: {pkt_len} bytes")

    # Detect port scanning behavior
    if ip_traffic[ip_src] > THRESHOLD_PORT_SCANS:
        detected_issues.append(f"Possible port scan detected from {ip_src}!")
        detected_threats.append(f"Threat: Port scanning from {ip_src}")

    # Detect unusual connections to the same destination
    if ip_traffic[ip_dst] > THRESHOLD_UNUSUAL_CONNECTIONS:
        detected_issues.append(f"Unusual connections detected to {ip_dst}!")
        detected_threats.append(f"Threat: Unusual connections to {ip_dst} from {ip_src}")

# Function to capture packets using Scapy
def packet_callback(packet):
    global captured_packets
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        pkt_len = len(packet)

        # Update packet data
        packet_data['Time'].append(timestamp)
        packet_data['Source IP'].append(ip_src)
        packet_data['Destination IP'].append(ip_dst)
        packet_data['Protocol'].append(proto)
        packet_data['Packet Length'].append(pkt_len)

        # Update traffic and protocol counters
        ip_traffic[ip_src] += 1
        ip_traffic[ip_dst] += 1  # Track destination IP traffic
        protocol_distribution[proto] += 1

        # Detect issues and threats based on packet behavior
        detect_issues(ip_src, pkt_len, ip_dst)

        # Update packet table in GUI
        update_packet_table(timestamp, ip_src, ip_dst, proto, pkt_len)

    # Stop sniffing if the flag is set to False
    if not sniffing:
        return False  # This will stop the sniffing
    
    # Save the actual packet object to captured_packets for later writing to PCAP
    captured_packets.append(packet)

# Function to update the packet table in the GUI
def update_packet_table(timestamp, ip_src, ip_dst, proto, pkt_len):
    # Insert a new row into the treeview
    tree.insert("", "end", values=(timestamp, ip_src, ip_dst, proto, pkt_len))

# Function to start packet sniffing
def start_sniffing():
    global sniffing
    sniffing = True  # Set the flag to True

    # The stop_filter argument will stop sniffing when sniffing is set to False
    sniff(prn=packet_callback, filter="ip", store=0, stop_filter=lambda x: not sniffing)

# Function to stop packet sniffing
def stop_sniffing():
    global sniffing
    sniffing = False  # Set the flag to False
    messagebox.showinfo("Network Monitoring", "Packet sniffing has stopped.")

def generate_packet_report():
    # Create a DataFrame for captured packets' metadata (as you already do)
    report_data = pd.DataFrame(packet_data)
    report_data['Packet Count'] = report_data.groupby(['Source IP', 'Destination IP', 'Protocol'])['Time'].transform('count')
    report_summary = report_data.groupby('Protocol').agg({
        'Packet Length': ['mean', 'sum', 'count']
    }).reset_index()
    report_summary.columns = ['Protocol', 'Avg Packet Length', 'Total Packet Length', 'Packet Count']

    # Save actual packets to a PCAP file
    report_filename = "packet_report.pcap"
    wrpcap(report_filename, captured_packets)  # Use captured_packets, not packet_data

    # Save summary report to CSV
    report_summary.to_csv("summary_packet_report.csv", index=False)

    messagebox.showinfo("Report Generated", f"Packet report saved as:\n- {report_filename}\n- summary_packet_report.csv")

# Function to generate threats report
def generate_threat_report():
    # Save detected issues and threats to report
    with open("threats_report.txt", "w") as f:
        f.write("Detected Issues:\n")
        f.write("\n".join(detected_issues) if detected_issues else "None")
        f.write("\n\nDetected Threats:\n")
        f.write("\n".join(detected_threats) if detected_threats else "None")

    messagebox.showinfo("Report Generated", "Threat report saved as:\n- threats_report.txt")

# Function to display the protocol distribution pie chart
def show_protocol_distribution():
    # Create a new figure for the protocol distribution pie chart
    fig, ax = plt.subplots()
    protocols, counts = zip(*protocol_distribution.items())
    ax.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    ax.set_title("Protocol Distribution")
    plt.show()

# Function to run packet sniffing in a separate thread
def start_sniffing_thread():
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    messagebox.showinfo("Network Monitoring", "Packet sniffing has started...")

# Function to update live traffic rate
def update_live_traffic(i):
    current_time = datetime.now()

    # Append the current time to the time intervals list
    time_intervals.append(current_time)

    # Count the number of packets in the last second
    count_last_second = len([t for t in packet_data['Time'] if t == time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())])
    packet_count_per_second.append(count_last_second)

    # Keep the last 60 seconds of data for live display
    if len(time_intervals) > 60:
        time_intervals.pop(0)
        packet_count_per_second.pop(0)

    # Update traffic rate plot
    ax_traffic.clear()
    ax_traffic.plot(time_intervals, packet_count_per_second, color='blue', label="Packets/sec")  # Removed marker='o'
    ax_traffic.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    ax_traffic.set_title("Live Traffic Rate")
    ax_traffic.set_xlabel("Time")
    ax_traffic.set_ylabel("Packets per second")

    # Hide gridlines
    ax_traffic.grid(False)

    # Set y-axis limits to avoid negative values
    ax_traffic.set_ylim(bottom=0)  # Set the lower limit to 0

    ax_traffic.legend(loc="upper right")

# Function to display the full traffic rate from start to end
def show_full_traffic_rate():
    fig_full, ax_full = plt.subplots()
    
    # Convert the timestamps to a datetime format
    timestamps = pd.to_datetime(packet_data['Time'])
    
    # Create a DataFrame to count packets over time
    packet_counts = timestamps.value_counts().sort_index()
    
    # Plot the data as a line graph
    ax_full.plot(packet_counts.index, packet_counts.values, color='blue')
    
    ax_full.set_title("Full Traffic Rate Over Time")
    ax_full.set_xlabel("Time")
    ax_full.set_ylabel("Packet Count")
    
    # Improve x-axis formatting
    ax_full.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    ax_full.xaxis.set_major_locator(mdates.MinuteLocator(interval=1))
    plt.xticks(rotation=45)
    
    plt.tight_layout()  # Adjust layout to prevent clipping
    plt.show()

# GUI Application
def create_gui():
    global tree, ax_traffic, window  # Make tree and ax accessible globally
    window = tk.Tk()  # Declare window globally
    window.title("Network Traffic Analysis Tool")

    # Maximize the window
    window.state('zoomed')  # Set to maximized

    # Configure the main window grid layout
    window.grid_rowconfigure(0, weight=1)
    window.grid_rowconfigure(1, weight=1)  # Divide into two equal halves
    window.grid_columnconfigure(1, weight=1)

    # Frame for the buttons (top-left corner)
    button_frame = tk.Frame(window)
    button_frame.grid(row=0, column=0, sticky='nw', padx=10, pady=10)

    # Button to start packet sniffing
    sniff_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing_thread, width=30, height=2)
    sniff_button.pack(pady=5)

    # Button to stop packet sniffing
    stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, width=30, height=2)
    stop_button.pack(pady=5)

    # Button to generate packet report
    report_button = tk.Button(button_frame, text="Generate Packet Report", command=generate_packet_report, width=30, height=2)
    report_button.pack(pady=5)

    # Button to generate threat report
    threat_report_button = tk.Button(button_frame, text="Generate Threat Report", command=generate_threat_report, width=30, height=2)
    threat_report_button.pack(pady=5)

    # Button to show protocol distribution
    protocol_button = tk.Button(button_frame, text="Show Protocol Distribution", command=show_protocol_distribution, width=30, height=2)
    protocol_button.pack(pady=5)

    # Button to show full traffic rate
    full_traffic_button = tk.Button(button_frame, text="Show Full Traffic Rate", command=show_full_traffic_rate, width=30, height=2)
    full_traffic_button.pack(pady=5)

    # Frame for the packet table (top-right corner)
    packet_frame = tk.Frame(window)
    packet_frame.grid(row=0, column=1, sticky='nsew', padx=10, pady=10)

    # Treeview for displaying captured packets
    tree = ttk.Treeview(packet_frame, columns=("Time", "Source IP", "Destination IP", "Protocol", "Packet Length"), show="headings")
    tree.heading("Time", text="Time")
    tree.heading("Source IP", text="Source IP")
    tree.heading("Destination IP", text="Destination IP")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Packet Length", text="Packet Length")
    tree.pack(fill="both", expand=True)

    # Frame for the live traffic rate plot (bottom half)
    traffic_frame = tk.Frame(window)
    traffic_frame.grid(row=1, column=0, columnspan=2, sticky='nsew', padx=10, pady=10)

    # Create a figure for live traffic rate
    fig_traffic, ax_traffic = plt.subplots()
    canvas = FigureCanvasTkAgg(fig_traffic, master=traffic_frame)
    canvas.get_tk_widget().pack(fill='both', expand=True)

    # Start the live traffic rate update   
    ani = FuncAnimation(fig_traffic, update_live_traffic, interval=400, cache_frame_data=False)  # Update every second

    # Run the GUI main loop
    window.mainloop()
    
if __name__ == "__main__":
    create_gui()