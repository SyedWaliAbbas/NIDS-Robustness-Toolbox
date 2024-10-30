# <img src="/logo.png" width="140" valign="middle"  />&nbsp; NIDS Robustness Toolbox (NRT)


The NIDS Robustness Toolbox (NRT) is a versatile tool designed to generate adversarial samples to test the robustness of machine learning-based Network Intrusion Detection Systems (NIDS). This toolbox includes functions for manipulating packet payloads, spoofing addresses, and camouflaging SQL queries, enabling users to simulate a variety of adversarial attacks. Below is an overview of the main functions provided by NRT, their attributes, and usage instructions.

## 1. Distributed Attack Generation: `only_distributed_attack`

This function enables IP and MAC address spoofing, primarily targeting Distributed Denial of Service (DDoS) attacks using SYN or ICMP packets. It scans all packets in a folder containing PCAP files, identifies packets from specified MAC addresses, and replaces the source MAC and IP addresses with randomly generated spoofed values.

**Attributes:**
- `input_folder`: Path to the folder containing PCAP files.
- `num_spoofed`: Number of unique IP-MAC pairs to generate.
- `target_mac_addresses`: List of MAC addresses to target.

**Usage:**  
This function is ideal for simulating DDoS attacks to assess how well a flow-based NIDS handles adversarial samples created through spoofed addresses, making it challenging to trace the attack origin.

---

## 2. TCP-Based Payload Manipulation Attack: `tcp_attack`

Designed for TCP-based adversarial attacks, this function allows users to add payloads to specific TCP packets based on their flags, which may include SYN, ACK, FIN, and others. Payload options include random or custom strings. Additionally, IP and MAC spoofing is available to further obfuscate the attack.

**Attributes:**
- `folder`: Folder containing the PCAP files.
- `target_mac_addresses`: List of target MAC addresses.
- `spoofing`: Enables spoofing of MAC and IP addresses if set to `True`.
- `spoof_addresses_num`: Number of unique spoofed addresses.
- `always_add`: Adds payload even in non-standard cases if `True`.
- `random_payload`: Adds a randomly generated payload if set to `True`.
- `byte_size`: Size of the payload in bytes.
- `custom_payload`: User-defined payload if random generation is disabled.
- `search_flag`: Specify TCP flags to control payload addition.

**Usage:**  
This function is useful for testing payload-based NIDS robustness by generating adversarial traffic that mimics TCP-based attacks, with options for finely controlled packet manipulations.

---

## 3. ICMP-Based Payload Manipulation Attack: `icmp_attack`

This function handles ICMP packets specifically, allowing users to add payloads and spoof source IP/MAC addresses. Like `tcp_attack`, users can choose between custom and random payloads. ICMP packets of types Echo Request (Type 8) and Echo Reply (Type 0) are targeted for payload addition, making it ideal for testing how well NIDS detect and manage ICMP-based DDoS attacks.

**Attributes:**
- `folder`: Folder containing the PCAP files.
- `target_mac_addresses`: List of MAC addresses to target.
- `spoofing`: Enables spoofing if set to `True`.
- `spoof_addresses_num`: Number of spoofed addresses.
- `always_add`: Adds payload unconditionally if set to `True`.
- `random_payload`: Generates a random payload if enabled.
- `byte_size`: Specifies the size of the payload.
- `custom_payload`: User-defined payload to insert.

**Usage:**  
ICMP-based NIDS evasion attacks can be generated, testing how well flow-based models differentiate benign ICMP packets from attack traffic.

---

## 4. SQL Camouflage Attack: `sql_attack`

For HTTP-based SQL injection attacks, this function scans HTTP payloads within TCP packets for SQL queries, identified by common SQL keywords. Comments are injected to obfuscate the SQL intent while preserving functionality. Users can choose between custom and random SQL comments.

**Attributes:**
- `folder`: Path to the folder with PCAP files.
- `target_mac_addresses`: List of MAC addresses from which to identify SQL packets.
- `random_payload`: If enabled, adds a randomly generated comment.
- `byte_size`: Size of random comment if used.
- `custom_payload`: Specifies a custom comment if random is disabled.

**Usage:**  
SQL camouflage attacks assess the vulnerability of NIDS focused on payload analysis, where obfuscation is done to bypass payload content-based detection of malicious SQL queries.

---

Each of these functions allows NIDS researchers and developers to assess their model’s resilience against specific types of adversarial attacks by generating realistic adversarial traffic directly from PCAP files. This model-agnostic approach makes the NRT suitable for testing a wide array of machine-learning-based NIDS, as it does not require prior knowledge of the NIDS’s processing pipeline, feature extraction, or model details.
