# SCADA-CIP-Discovery
Common Industrial Protocol based device scanner over the internet
This program needs more refinement. The response packets are not displayed.
Use wireshark when ruiing this script with the filter set to enip to view the response data for analysis
Run using "python cipscan.py 127.0.0.0/24"
A usual response packet will contain information like this

Vendor ID: Rockwell Automation/Allen-Bradley (0x0001)
Device Type: Programmable Logic Controller (14)
Product Code: XX
Revision: 2.11
Status: 0x0004
Serial Number: 0xXXXXXXdX
Product Name Length: XX
Product Name: XXXX-LXXBXB B/XX.XX
State: 0x00

In addition to this the private IP addresses of the system will also be included like 192.168.0.17
