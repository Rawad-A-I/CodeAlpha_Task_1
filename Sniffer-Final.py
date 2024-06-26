from simple_term_menu import TerminalMenu
from scapy.all import sniff
import threading
import sys

# Initialize global variables
captured_packets = []  # List to store captured packets
sniffer_thread = None  # Thread for the sniffer
sniffing = False       # Flag to check if sniffing is active
nump = None            # Number of packets to capture (None by default)
filter_ip = None       # Filter by IP address
filter_protocol = None # Filter by protocol
filter_port = None     # Filter by port
progress = 0           # Progress of packet capture

# Callback function to handle each captured packet
def packet_callback(packet):
    if packet_filter(packet):
        captured_packets.append(packet)
        update_progress()
        print_progress()

# Function to update progress
def update_progress():
    global progress
    if nump:
        progress = (len(captured_packets) / nump) * 100

# Function to print progress
def print_progress():
    sys.stdout.write(f"\rProgress: {progress:.2f}% | Captured {len(captured_packets)} packets")
    sys.stdout.flush()

# Function to filter packets based on user input
def packet_filter(packet):
    if filter_ip:
        if packet.haslayer('IP') and (packet['IP'].src != filter_ip and packet['IP'].dst != filter_ip):
            return False

    if filter_protocol:
        if filter_protocol.upper() == "TCP" and not packet.haslayer('TCP'):
            return False
        if filter_protocol.upper() == "UDP" and not packet.haslayer('UDP'):
            return False
        if filter_protocol.upper() == "HTTP" and not packet.haslayer('HTTP'):
            return False
        if filter_protocol.upper() == "DNS" and not packet.haslayer('DNS'):
            return False

    if filter_port:
        if packet.haslayer('TCP') and (packet['TCP'].sport != filter_port and packet['TCP'].dport != filter_port):
            return False
        if packet.haslayer('UDP') and (packet['UDP'].sport != filter_port and packet['UDP'].dport != filter_port):
            return False

    return True

# Function to analyze captured packets
def analyze_packet(packet):
    try:
        source_ip = packet['IP'].src
        destination_ip = packet['IP'].dst
        protocol = packet['IP'].proto

        source_port = packet['TCP'].sport if packet.haslayer('TCP') else (packet['UDP'].sport if packet.haslayer('UDP') else 'N/A')
        destination_port = packet['TCP'].dport if packet.haslayer('TCP') else (packet['UDP'].dport if packet.haslayer('UDP') else 'N/A')
        payload = bytes(packet['TCP'].payload) if packet.haslayer('TCP') else (bytes(packet['UDP'].payload) if packet.haslayer('UDP') else b'N/A')

        print(f"\n[+] Analyzing Packet:")
        print(f"    Source IP: {source_ip}")
        print(f"    Destination IP: {destination_ip}")
        print(f"    Protocol: {protocol}")
        print(f"    Source Port: {source_port}")
        print(f"    Destination Port: {destination_port}")
        print(f"    Payload: {payload}")

        # Detailed Protocol Analysis
        if packet.haslayer('HTTP'):
            print("[+] HTTP Packet Detected")
            print(f"    HTTP Payload: {str(packet['HTTP'].payload)}")
        
        if packet.haslayer('DNS'):
            print("[+] DNS Packet Detected")
            print(f"    DNS Query: {packet['DNS'].qd.qname}")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to start sniffing packets
def start_sniffing():
    global sniffer_thread, sniffing, nump, progress
    if not sniffing:
        if nump is None:
            try:
                # Ask user for the number of packets to capture
                nump = int(input("Enter the number of packets to capture (integer): "))
            except ValueError:
                print("Invalid input. Using default number of packets (10).")
                nump = 10

        sniffing = True
        progress = 0
        print("\n[+] Sniffer started...\n")
        # Create and start a new thread for sniffing packets
        sniffer_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=0, stop_filter=lambda x: len(captured_packets) >= nump))
        sniffer_thread.start()

# Function to stop sniffing packets
def stop_sniffing():
    global sniffing
    if sniffing:
        sniffing = False
        sniffer_thread.join()  # Wait for the sniffer thread to finish
        print("\n[+] Sniffer stopped.")

# Function to display statistics of captured packets
def display_statistics():
    print(f"\nTotal captured and analyzed packets: {len(captured_packets)}")
    for packet in captured_packets:
        analyze_packet(packet)

# Function to display the help menu
def display_help():
    print("\n--- Help Menu ---")
    print("1. Start Sniffing: Begin capturing packets.")
    print("2. Stop Sniffing: Stop capturing packets.")
    print("3. Display Statistics: Show details of captured packets.")
    print("4. Advanced Features: Set filters and number of packets.")
    print("5. Help: Show this help menu.")
    print("6. Exit: Exit the program.")

# Function to display the advanced features help menu
def display_advanced_help():
    print("\n--- Advanced Features Help Menu ---")
    print("1. Set Number of Packets: Specify the number of packets to capture.")
    print("2. Set Filter IP: Filter packets by IP address.")
    print("3. Set Filter Protocol: Filter packets by protocol (TCP, UDP, HTTP, DNS).")
    print("4. Set Filter Port: Filter packets by port.")
    print("5. Help: Show this help menu.")
    print("6. Exit: Exit advanced features menu and go back to the main menu.")

# Function to set the number of packets to capture
def set_num_packets():
    global nump
    try:
        nump = int(input("Enter the number of packets to capture: "))
    except ValueError:
        print("Invalid input. Using default number of packets (10).")
        nump = 10

# Function to set the IP filter
def set_filter_ip():
    global filter_ip
    filter_ip = input("Enter the IP address to filter by: ")

# Function to set the protocol filter
def set_filter_protocol():
    global filter_protocol
    filter_protocol = input("Enter the protocol to filter by (TCP, UDP, HTTP, DNS): ")

# Function to set the port filter
def set_filter_port():
    global filter_port
    try:
        filter_port = int(input("Enter the port to filter by: "))
    except ValueError:
        print("Invalid input. No port filter will be applied.")
        filter_port = None

# Advanced features menu function
def advanced_menu():
    options = [
        "Set Number of Packets",
        "Set Filter IP",
        "Set Filter Protocol",
        "Set Filter Port",
        "Help",
        "Exit"
    ]
    terminal_menu = TerminalMenu(options, title="--- Advanced Features Menu ---")
    while True:
        choice = terminal_menu.show()
        if choice == 0:
            set_num_packets()  # Set the number of packets to capture
        elif choice == 1:
            set_filter_ip()    # Set the IP filter
        elif choice == 2:
            set_filter_protocol()  # Set the protocol filter
        elif choice == 3:
            set_filter_port()   # Set the port filter
        elif choice == 4:
            display_advanced_help()  # Display the advanced features help menu
        elif choice == 5:
            break  # Exit advanced features menu and go back to the main menu

# Main menu function for user interaction
def menu():
    options = [
        "Start Sniffing",
        "Stop Sniffing",
        "Display Statistics",
        "Advanced Features",
        "Help",
        "Exit"
    ]
    terminal_menu = TerminalMenu(options, title="--- Network Sniffer Menu ---")
    while True:
        choice = terminal_menu.show()
        if choice == 0:
            start_sniffing()  # Start sniffing packets
        elif choice == 1:
            stop_sniffing()   # Stop sniffing packets
        elif choice == 2:
            display_statistics()  # Display statistics of captured packets
        elif choice == 3:
            advanced_menu()  # Go to advanced features menu
        elif choice == 4:
            display_help()  # Display the help menu
        elif choice == 5:
            if sniffing:
                stop_sniffing()  # Stop sniffing before exiting if it's running
            print("Exiting...")
            sys.exit()

if __name__ == "__main__":
    menu()  # Start the menu
