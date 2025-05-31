# Network-Information-Tool

A cross-platform Python tool that collects and displays essential network information including:

- Routing Tables
- Network Interfaces
- ARP Cache
- DNS Configuration
- Default Gateways

## Features

✅ Supports Windows, Linux, and macOS  
✅ Displays output in a clean, tabular format  
✅ Detects and shows gateway, MAC addresses, broadcast, and interface info  
✅ Easy to run, just a single Python file

## Requirements

- Python 3.6 or newer
- `netifaces`
- `prettytable`

Install dependencies with:

```bash
pip install -r requirements.txt

How to Run
Clone or download the project, then run the script:

python3 network_analyzer.py

================================================================================
                             NETWORK INFORMATION TOOL                           
================================================================================

--------------------------------- ROUTING TABLE --------------------------------
+-------------+-------------+---------------+-----------+--------------------+
| Destination | Gateway     | Netmask       | Interface | Metric/Flags       |
+-------------+-------------+---------------+-----------+--------------------+
| 0.0.0.0     | 192.168.1.1 | 0.0.0.0       | eth0      | 100                |
...

------------------------------ NETWORK INTERFACES ------------------------------
+-----------+-------------+---------------+-------------------+-------------+
| Interface | IP Address | Netmask       | MAC Address       | Broadcast   |
+-----------+-------------+---------------+-------------------+-------------+
| eth0      | 192.168.1.2 | 255.255.255.0 | AA:BB:CC:DD:EE:FF | 192.168.1.255 |
...

------------------------------ DEFAULT GATEWAYS -------------------------------
+--------+-------------+-----------+
| Type   | Gateway IP  | Interface |
+--------+-------------+-----------+
| IPv4   | 192.168.1.1 | eth0      |
...

----------------------------------- ARP TABLE ----------------------------------
Interface: eth0
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
...

------------------------------ DNS INFORMATION ---------------------------------
nameserver 8.8.8.8
nameserver 1.1.1.1
...

## Notes

- On Unix systems, the tool uses `netstat`, `arp`, and `cat /etc/resolv.conf`.
- On Windows, it uses `route print`, `arp -a`, and `ipconfig /all`.

## License

MIT License

## Author

[Phone Myint Kyaw]

