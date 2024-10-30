## distribute syn and icmp attacks 
import dpkt
import os
import random
import re
import urllib.parse
from scapy.all import rdpcap, wrpcap, Ether, TCP, IP, Raw, ICMP


# Function to generate random MAC address
def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255), random.randint(0, 255),
        random.randint(0, 255), random.randint(0, 255),
        random.randint(0, 255)
        )
    
     

# Function to generate random IP address
def random_ip():
    return "192.168.%d.%d" % (random.randint(0, 255), random.randint(1, 254))
    
    

# Function to process PCAP files in a folder
def only_distributed_attack(input_folder, num_spoofed, target_mac_addresses):
    # Generate unique combinations of IP and MAC addresses
    print('*'*20)
    print('Spoofed Mac and IP addresses are......')
    spoofed_addresses = [(random_mac(), random_ip()) for _ in range(num_spoofed)]
    print(spoofed_addresses)
    print('*'*20)
    
    # Iterate over files in the input folder
    for file_name in os.listdir(input_folder):
        if file_name.endswith(".pcap"):
            print('Processing :',file_name,' .........')
            input_file_path = os.path.join(input_folder, file_name)
            output_file_path = os.path.join(input_folder, 'modified_' + file_name)

            # Open the PCAP file using dpkt
            with open(input_file_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                # List to store modified packets
                modified_packets = []
                spoof_index = 0  # To track which spoofed address we're using
                
                # Process each packet
                for ts, buf in pcap:
                    # Use Scapy to manipulate the packet
                    scapy_packet = Ether(buf)
                    
                    # Check if the source MAC address is in the target list
                    if scapy_packet.src in target_mac_addresses:
                        # Replace with a new MAC and IP address from the spoofed list
                        new_mac, new_ip = spoofed_addresses[spoof_index % num_spoofed]
                        
                        try:
                            scapy_packet[IP].src = new_ip
                            scapy_packet.src = new_mac
                        except:
                            print(f"IP layer not found in packet from {scapy_packet.src}")
                        
                        # Update the index for the next packet
                        spoof_index += 1
                    
                    # Add the modified packet to the list
                    modified_packets.append(scapy_packet)
            
            # Save the modified packets to a new PCAP file
            wrpcap(output_file_path, modified_packets)
            print(f"Modified file saved as: {output_file_path}")
            
            
# Function to generate random payload of given byte size
def generate_random_payload(byte_size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=byte_size)).encode()

# Function to process all PCAP files in a given folder with specified parameters
def tcp_attack(folder,target_mac_addresses, spoofing=True, spoof_addresses_num=20, always_add=True, random_payload=False, byte_size=100, custom_payload=None, 
                      search_flag=None,prints=True):
    # Generate unique spoofed MAC and IP addresses based on the given number
    
    print('*'*20)
    print('Spoofed Mac and IP addresses are......')
    spoofed_addresses = [(random_mac(), random_ip()) for _ in range(spoof_addresses_num)]
    print(spoofed_addresses)
    print('*'*20)
    
    
    # Define TCP flag to standard payload behavior mapping
    tcp_flag_behavior = {
        'S': "Usually no payload.",
        'SA': "Usually no payload.",
        'A': "Payload is common (piggybacking).",
        'F': "Payload possible but often empty.",
        'R': "Usually no payload (non-standard).",
        'P': "Payload is expected (immediate delivery).",
        'PA': "Payload is common.",
        'U': "Payload is common (urgent data).",
        'UA': "Payload is common (urgent + acknowledgment).",
        'RA': "Payload is rare/non-standard."
    }
    
    # Function to process and print TCP flag behavior
    def check_and_add_payload(tcp_layer, packet_flags, always_add, random_payload, byte_size, custom_payload,search_flag,prints):
        flag_str = ''.join(packet_flags)
        standard_behavior = tcp_flag_behavior.get(flag_str, "Unknown behavior")

        if search_flag== None:
            # If always_add is set to True, add payload but print a warning once
            if always_add:
                if prints:
                    print(f"Warning: Adding payload to {flag_str} flag combination. This is {standard_behavior}.")
                return Raw(load=generate_random_payload(byte_size) if random_payload else custom_payload)
            
            # If always_add is False, check flag condition and add payload accordingly
            if flag_str in ['S', 'SA', 'R', 'RA']:
                if prints:
                    print(f"Skipping payload for {flag_str} flag combination. {standard_behavior}")
                return None  # No payload added for non-standard combinations
            else:
                if prints:
                    print(f"Standard payload addition for {flag_str} flag combination. {standard_behavior}")
                return Raw(load=generate_random_payload(byte_size) if random_payload else custom_payload)
        else:
            if flag_str in search_flag:
                return Raw(load=generate_random_payload(byte_size) if random_payload else custom_payload)
    
    # Process all PCAP files in the specified folder
    for file_name in os.listdir(folder):
        if file_name.endswith(".pcap"):
            file_path = os.path.join(folder, file_name)
            
            with open(file_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                # List to store modified packets
                modified_packets = []
                spoof_index = 0  # To track which spoofed address we're using
                
                # Process each packet
                for ts, buf in pcap:
                    # Use Scapy to manipulate the packet
                    scapy_packet = Ether(buf)
                    
                    # Check if it's an Ethernet packet and has an IP and TCP layer
                    if scapy_packet.haslayer(IP) and scapy_packet.haslayer(TCP):
                        # Extract original layers
                        ip_layer = scapy_packet[IP]
                        tcp_layer = scapy_packet[TCP]
                        
                        # Get the flags of the TCP packet
                        flags = tcp_layer.sprintf("%TCP.flags%")
                        
                        # Only process if the MAC address is in the target list
                        if scapy_packet.src in target_mac_addresses:
                            
                            # Check if adding payload is appropriate for this flag combination
                            new_payload = check_and_add_payload(tcp_layer, flags, always_add, random_payload, byte_size, custom_payload,search_flag,prints)
                            
                            if new_payload:
                                tcp_layer.payload = new_payload  # Add the custom or random payload
                            
                            # Perform spoofing only if the user sets spoofing=True
                            if spoofing:
                                new_mac, new_ip = spoofed_addresses[spoof_index % spoof_addresses_num]
                                ip_layer.src = new_ip
                                scapy_packet.src = new_mac
                                if prints:
                                    print(f"Spoofing: Replacing MAC and IP with {new_mac}, {new_ip}")
                            
                            # Set checksums to None to force recalculation
                            ip_layer.chksum = None  # Recalculate IP checksum
                            tcp_layer.chksum = None  # Recalculate TCP checksum
                            
                            # Rebuild the entire packet by setting the updated TCP and IP layers
                            new_packet = Ether(src=scapy_packet.src, dst=scapy_packet.dst) / IP(src=ip_layer.src, dst=ip_layer.dst) / tcp_layer
                            
                            # Increment the spoof index for the next packet
                            spoof_index += 1
                            
                            # Add the modified packet to the list
                            modified_packets.append(new_packet)
                            
                    # Add unmodified packets as well
                    else:
                        modified_packets.append(scapy_packet)
            
            # Save the modified packets to a new PCAP file with 'modified_' prefix
            modified_file_path = os.path.join(folder, f"modified_{file_name}")
            wrpcap(modified_file_path, modified_packets)
            print(f"Processed and saved modified PCAP: {modified_file_path}")
            
            
# Function to process all PCAP files in a given folder, add payload to ICMP packets, and optionally spoof addresses
def icmp_attack(folder, target_mac_addresses, spoofing=True, spoof_addresses_num=20, always_add=True, random_payload=False,
                            byte_size=100, custom_payload=None,prints=False):
    # Generate unique spoofed MAC and IP addresses based on the given number
    
    
    print('*'*20)
    print('Spoofed Mac and IP addresses are......')
    spoofed_addresses = [(random_mac(), random_ip()) for _ in range(spoof_addresses_num)]
    print(spoofed_addresses)
    print('*'*20)
    
    # Function to add payload to ICMP packets
    def check_and_add_icmp_payload(icmp_layer, always_add, random_payload, byte_size, custom_payload):
        # If always_add is set to True, add payload but print a warning once
        if always_add:
            if prints:
                print(f"Adding payload to ICMP packet.")
            return Raw(load=generate_random_payload(byte_size) if random_payload else custom_payload)
        else:
            # Adding payload if appropriate
            if icmp_layer.type in [0, 8,42,43]:  # Echo Reply and Echo Request
                if prints:
                    print(f"Adding payload to ICMP Echo Request/Reply packet.")
                return Raw(load=generate_random_payload(byte_size) if random_payload else custom_payload)
            else:
                if prints:
                    print(f"Skipping payload addition for non-echo ICMP packet.")
                return None
    
    # Process all PCAP files in the specified folder
    for file_name in os.listdir(folder):
        if file_name.endswith(".pcap"):
            file_path = os.path.join(folder, file_name)
            
            with open(file_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                # List to store modified packets
                modified_packets = []
                spoof_index = 0  # To track which spoofed address we're using
                
                # Process each packet
                for ts, buf in pcap:
                    # Use Scapy to manipulate the packet
                    scapy_packet = Ether(buf)
                    
                    # Check if it's an Ethernet packet and has an IP and ICMP layer
                    if scapy_packet.haslayer(IP) and scapy_packet.haslayer(ICMP):
                        # Extract original layers
                        ip_layer = scapy_packet[IP]
                        icmp_layer = scapy_packet[ICMP]
                        
                        # Only process if the MAC address is in the target list
                        if scapy_packet.src in target_mac_addresses:
                            
                            # Check if adding payload is appropriate for this ICMP packet
                            new_payload = check_and_add_icmp_payload(icmp_layer, always_add, random_payload, byte_size, custom_payload)
                            
                            if new_payload:
                                icmp_layer.payload = new_payload  # Add the custom or random payload
                            
                            # Perform spoofing only if the user sets spoofing=True
                            if spoofing:
                                new_mac, new_ip = spoofed_addresses[spoof_index % spoof_addresses_num]
                                ip_layer.src = new_ip
                                scapy_packet.src = new_mac
                                if prints:
                                    print(f"Spoofing: Replacing MAC and IP with {new_mac}, {new_ip}")
                            
                            # Set checksums to None to force recalculation
                            ip_layer.chksum = None  # Recalculate IP checksum
                            icmp_layer.chksum = None  # Recalculate ICMP checksum
                            
                            # Rebuild the entire packet by setting the updated IP and ICMP layers
                            new_packet = Ether(src=scapy_packet.src, dst=scapy_packet.dst) / IP(src=ip_layer.src, dst=ip_layer.dst) / icmp_layer
                            
                            # Increment the spoof index for the next packet
                            spoof_index += 1
                            
                            # Add the modified packet to the list
                            modified_packets.append(new_packet)
                            
                        else:
                            # Add unmodified packets if MAC is not in the list
                            modified_packets.append(scapy_packet)
                    else:
                        # Add unmodified packets if not an ICMP packet
                        modified_packets.append(scapy_packet)
            
            # Save the modified packets to a new PCAP file with 'modified_' prefix
            modified_file_path = os.path.join(folder, f"modified_{file_name}")
            wrpcap(modified_file_path, modified_packets)
            print(f"Processed and saved modified ICMP PCAP: {modified_file_path}")


##**************************SQL ATTACK Portion*****************************************************************


# Function to generate random comment payload of a given byte size
def generate_random_comment(byte_size):
    return ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=byte_size))

# Function to add multi-line comments to specific places in the SQL query
def add_comment_to_sql(query, random_payload=False, byte_size=100, custom_payload=None):
    # Decide on the payload (random or custom)
    if random_payload:
        payload = f"/* {generate_random_comment(byte_size)} */"
    else:
        payload = f"/* {custom_payload} */"
    
    # Strategy to inject comments before specific keywords
    comment_injections = {
        'UNION': f'{payload} UNION',
        'SELECT': f'{payload} SELECT',
        'FROM': f'{payload} FROM',
        'WHERE': f'{payload} WHERE',
        'ORDER BY': f'{payload} ORDER BY'
    }
    
    # Inject comments at the correct places in the SQL query
    for keyword, comment_keyword in comment_injections.items():
        query = re.sub(f'\\b{keyword}\\b', comment_keyword, query, flags=re.IGNORECASE)
    
    return query

# Function to process PCAP files, check MAC address, identify SQL queries in HTTP traffic, and modify them
def sql_attack(folder, target_mac_addresses, random_payload=False, byte_size=100, custom_payload=None):
    # Process all PCAP files in the specified folder
    for file_name in os.listdir(folder):
        if file_name.endswith(".pcap"):
            file_path = os.path.join(folder, file_name)
            
            # Read the PCAP file using scapy
            packets = rdpcap(file_path)
            
            modified_packets = []  # List to store modified packets
            
            print(f"Processing file: {file_name}")
            for pkt in packets:
                # Check if it's an Ethernet packet (contains MAC addresses)
                if pkt.haslayer(Ether):
                    src_mac = pkt[Ether].src  # Get the source MAC address
                    
                    # Only proceed if the source MAC address is in the target list
                    if src_mac in target_mac_addresses:
                        # Check if the packet is a TCP packet with HTTP-based data (likely contains SQL queries)
                        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                            raw_data = pkt[Raw].load.decode(errors='ignore')  # Extract raw TCP payload
                            
                            # Print all HTTP payloads found in the PCAP
                            if "HTTP" in raw_data.upper():
                                #print(f"HTTP Payload Found: {raw_data}")
                                
                                # Split the HTTP request into the first line (method and URL) and the headers
                                http_request_lines = raw_data.split("\r\n")
                                http_request_line = http_request_lines[0]
                                http_headers = "\r\n".join(http_request_lines[1:])

                                # Extract the URL and query parameters from the first line (GET /path?query HTTP/1.1)
                                method, full_url, http_version = http_request_line.split(" ")

                                # URL-decode the full URL to extract the original query
                                decoded_url = urllib.parse.unquote(full_url)

                                # Check if the packet contains an SQL query by looking for keywords
                                sql_keywords = '|'.join([r'\b{}\b'.format(k) for k in [
                                    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'TRUNCATE',
                                    'REPLACE', 'EXECUTE', 'MERGE', 'UNION', 'JOIN', 'ORDER BY', 'GROUP BY', 'HAVING',
                                    'DISTINCT', 'EXISTS', 'LIMIT', 'OFFSET', 'VALUES', 'INTO', 'WITH', 'AS'
                                ]])
                                
                                if re.search(sql_keywords, decoded_url, re.IGNORECASE):
                                    #print(f"Original SQL Query Found in HTTP Payload: {decoded_url}")
                                    
                                    # Modify the SQL query by adding comments at specific places
                                    modified_sql_query = add_comment_to_sql(decoded_url, random_payload, byte_size, custom_payload)
                                    
                                    # URL-encode only the modified query part
                                    encoded_modified_url = urllib.parse.quote(modified_sql_query)

                                    # Reconstruct the HTTP request
                                    modified_http_request_line = f"{method} {encoded_modified_url} {http_version}"
                                    modified_http_request = f"{modified_http_request_line}\r\n{http_headers}"
                                    
                                    # Replace the original payload with the modified query
                                    pkt[Raw].load = modified_http_request.encode()

                                    # Ensure proper encoding and length calculations
                                    modified_packet = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / \
                                                      IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                                                      TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack) / \
                                                      Raw(load=modified_http_request.encode())  # Ensure proper encoding

                                    # Recalculate checksums for IP and TCP
                                    del modified_packet[IP].chksum
                                    del modified_packet[TCP].chksum

                                    # Print the modified query
                                    #print(f"Modified SQL Query in HTTP Payload: {modified_http_request}")
                                    
                                    # Add the modified packet to the list
                                    modified_packets.append(modified_packet)
                                else:
                                    # If no SQL query found, add the original packet
                                    modified_packets.append(pkt)
                            else:
                                # If it's not HTTP traffic, add the original packet
                                modified_packets.append(pkt)
                        else:
                            # If it's not a TCP packet with raw data, add the original packet
                            modified_packets.append(pkt)
                    else:
                        # If the MAC address is not in the target list, add the original packet
                        modified_packets.append(pkt)
                else:
                    # If it's not an Ethernet packet, add the original packet
                    modified_packets.append(pkt)
            
            # Save the modified packets to a new PCAP file with 'modified_' prefix
            modified_file_path = os.path.join(folder, f"modified_{file_name}")
            wrpcap(modified_file_path, modified_packets)  # Use the wrpcap function to save modified packets
            print(f"Processed and saved modified PCAP: {modified_file_path}")



