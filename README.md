# python-ethsec

Phase 1:

1. Created Github python-ethsec repo

2. Kali Linux Machine: Installed UTM on Mac with Metasploit

**Running nmap -sV -O on MS Target**

<img width="729" height="597" alt="Screenshot 2025-10-11 at 7 06 25 PM" src="https://github.com/user-attachments/assets/1901333f-2efb-47c7-9645-9f15a33deb7c" />


**Master Notes**

[Internet Hacking 
](https://www.youtube.com/watch?v=dZwbb42pdtg)


**Subnetting (NC)**

Subnet Mask - Tells us how big our network is and how many IPs we have. 

_Turning Binary Code to Decimal_

1. power 2's table

128   64   32   16   8   4   2   1

2. 1 = on, 0 = off

3. decode using code per octet

Binary: 11000000 . 10101000 . 00000001 . 00010101
Decimal: 192.168.1.21

11000000 . 10101000. 000100000 . 00000101 = 192.168.32.5
11111111 . 11111111. 111111111 . 00000000 = 255.255.255.0

How to find out how many IP addresses can be on this network ^^
2^n = n = number of zeros (host bits)
2^8 = 256
256 - 2 (subtract the two unusuable IP addresses, first and last one)
254 = Usable IPS

Q - I need more IP addresses what do I do? 

11000000 . 10101000. 000100000 . 00000101 = 192.168.32.5
11111111 . 11111111. 111111110 . 00000000 = 255.255.254.0

More networks = more bits... steal them from the hosts (0). Below example needs 4 more networks, create second nose person chart

128  64  32  16  8  4  2  1
256  128 64  32  16 8  4  2

<img width="1869" height="975" alt="image" src="https://github.com/user-attachments/assets/2823479d-1bb3-44a1-8229-8f1a01746da7" />

 <img width="1907" height="1050" alt="image" src="https://github.com/user-attachments/assets/94df45f4-5e83-4447-ba7c-94b63b2a4a10" />


**TryHackMe CyberSecurity Foundamentals**

_Types of Browsers_

[Shohan](https://www.shodan.io/): Search engine for browsers connected to internet

[Censys](https://search.censys.io/): Used to search for specifi queries (IP addresses, domains, breaches of security)

[VirusTotal](https://www.virustotal.com/gui/home/upload): Scans files for viruses

[HaveIBeenPwned](https://haveibeenpwned.com/): Shows if an email address has been in a leak (HIBP)

Types of Vulnerabilities and Exploits:

[CVE](urlhttps://www.cve.org/): Common Vulnerabilities and Exploits. Search engine for vulnderabilities

[Exploit Database](https://www.exploit-db.com/): Provides working exploit codes

**Network Concepts**

ISO: International Organization for Standardization

_OSI Model: Open Systems Interconnection, conceptual model created by the OSI. People Do Nothing To Save People's Asses_

7. Application Layer
   - Providing services and interfaces to applications
   - ex: HTTP, FTP, DNS, POP3, SMTP, IMAP
   
6. Presentation Layer
   - Makes sure the data is presentable (encoding, compression and encryption)
   - ex: ASCII or Unicode
   
5. Session Layer
   - Responsible for maintaining and synchronizing communication between application running on different hosts.
   - ex: NFS (Network File System) and RPC (Remote Procedure Call)
   
4. Transport Layer
   - Enables end-to-end communcation between running applicatations on different hosts
   - ex: TCP (Transmission Control Protocol) and UDP (User Datagram Protocol)
   
3. Network Layer
   - Concerned with sending data between different networks.
   - ex: IP (internet protocol), ICMP (Internet Control Message Protocol), VPN (Virtual Private Network - IPSex and SSL/TLS VPN
   
Layer 2: Data Link Layer
   - The medium to transfer the signal through devices under the same network (i.e offices linked with a network switch)
   - ex: MAC address (Media Access Control)

<img width="985" height="550" alt="image" src="https://github.com/user-attachments/assets/cd8bf97c-f0fe-4a94-963d-819736398a9b" />

Layer 1: Physical Layer
   - The physical connection between devices (optical fibre cable, WIFI radio bands, 2.4G/5/6 Hz bands
   - medium: type of wire and the definition of the binary digits 0 and 1

_TCP/IP Model: developed in 1970s by the DoD. Goes top to bottom using the below layers_

Layer 5, 6, 7: Application Layer - It all starts when the user inputs the data they want to send into the application. For example, you write an email or an instant message and hit the send button. The application formats this data and starts sending it according to the application protocol used, using the layer below it, the transport layer.

Layer 4: Transport Layer - The transport layer, such as TCP or UDP, adds the proper header information and creates the TCP segment (or UDP datagram). This segment is sent to the layer below it, the network layer.

Layer 3: Internet Layer - The transport layer, such as TCP or UDP, adds the proper header information and creates the TCP segment (or UDP datagram). This segment is sent to the layer below it, the network layer.

Layer 2: Data Link Layer - The Ethernet or WiFi receives the IP packet and adds the proper header and trailer, creating a frame.

_RFC 1918 defines the following three ranges of private IP addresses:
_
    10.0.0.0 - 10.255.255.255 (10/8)
    172.16.0.0 - 172.31.255.255 (172.16/12)
    192.168.0.0 - 192.168.255.255 (192.168/16)

_UDP and TCP_

UDP: User Datagram Protocol - Connectionless. Does not provide confirmation that data packets have been received by the destination. 
- Functions in Layer 4 - Transport
- Uses port numbers to identify destination (between 1 and 65535
- Faster than TDP because no confirmation is needed

TCP: Transmission Control Protocol - Connection based. 
- Layer 4 protocol
- Requires established connection before data can be sent
- Sequence number used to identify data --> receiver acknowledges data has been received
- Three-way-handshake
 1. SYN Packet: Client initiates request by sending SYN packet to the server (contains the client's randomly chosesn initial sequence number)
 2. SYN-ACK Packet: Server responds with a SYN-ACK packet with their randomly chosen number
 3. ACK Packet: Client sends an ACK packet to acknowledge the reception of the SYN-ACK Packet

<img width="937" height="475" alt="image" src="https://github.com/user-attachments/assets/63194c38-1295-471b-a49d-d495b8769e73" />


Encapsulation: Every layer adding a header (sometimes a trailer)

<img width="986" height="357" alt="image" src="https://github.com/user-attachments/assets/fe0bc2a3-456a-4a01-ae00-fb55db552b37" />

**Network Essentials**

To access network need:
1. IP address along w/ subnet mask
2. Router (gateway/oprah)
3. DNS server

DHCP (Dynamic Host Configuration Protocol): Application level relies on UDP (server listens on UDP port  67, client sends from UDP port 68. Relies on DORA
- Discover: client broadcasts a DHCPDISCOVER message seeking the locak DHCP server if one exists
- Offer: Server responds with a DHCPOFFER message with an IP address available for the client to accept
- Request: client responds with a DHCPREQUEST message to indicate that it has accepted the offered IP
- Acknowledge: Server responds with a DHCPACK message to confirm that the offered IP address is now assigned to the client.

ARP (Address Resolution Protocol): Layer 2 - deals w/MAC addresses. makes it possible to find the MAC address of another device on the same ethernet

<img width="982" height="568" alt="image" src="https://github.com/user-attachments/assets/76518e54-a709-40bb-9703-57a4f79c4640" />

ICMP (Internet Control Message Protocol): 
- Ping: makes sure target is alive and measure RTT (round-trip time) to get the response back to the client
- traceroute: discovers the route from your host to the target

Routing Algorithms:
- OSPF (Open Shortest Path First): calculates most efficient path for data transmission.
- EIGRP (Enhanced Interior Gateway Routing Protocol): CISCO routing protocol - uses different routing algorithms too confirm which network will have the lest cost (delay)
- BGP (Border Gateway Protocol): Primary routing protocol - allows for differnt ISPs to exchange routing information and establish paths to travel between those networks
- RIP (Routing Information Protocol): Used for smaller networks. Routers share info about the networks they can reach and the number of hops (routers) required to get there. 

NAT (Network Address Translation): Allows for seamless translation of multiple private (devices) on a network 

**WINDOWS**

- To create an Azure Microsoft VM (https://youtu.be/X1CM3rZwGn8?si=GN8qGVM63flvn_Jn)

_Active Directory_

- Client --> Server --> DC (Domain Controller)
- Trees --> multiple domains sharing the same namespace(thm.local). USA & UK can share the same domains but they would have their own active directories, servers, and computers. (usa.thm.local & uk.thm.local)
- Forests --> Acquisition of another company. The joining of trees under the same network
- Trust relationships (one way and two way). Allows uk.thm.local user to access data in a server for acquision (ex MHT.Asia)

_Windows Command Line_

set: shows you the path that the commands will be executed in 

ver: shows version of OS 

systeminfo: shows detailed OS information, system details, processor and memory

| more: pipes it into a more readable format where you can move through pages using space.

driverquery: information about the system driver

ipconfig: shows IP address, subnet mask, and default gateway2

ipconfig /all: more information about network config including BNS and DHCP

DNS: Domain Name Systems - responsible for resolving hostnames to their respective IP addresses

DHCP: Dynamic Host Configuration Protocol - Network management tool used to automatically assign IP addresses and other communication parameters to devices connected to the network

ping target_name: if a server is up. We send a request they send one back. measured by milliseconds (ms)

tracert: traces the route that the ping took place. how many routers it jumped
<img width="1216" height="680" alt="image" src="https://github.com/user-attachments/assets/d657c77f-6640-488e-a257-0d348b202d27" />

nslookup domainname: looks up the ip address for whatever domain name you insert

netstat: displays the current network connections and listening ports. port 22 = SSH 
- -a: displays all established connections and listening ports
- -b: shows the program associated with each listening port and established connection
- -o reveals the process ID PID associated with the connection
- -n uses a numerical form for addresses and port numbers

dir: view child directories
- dir /a: displays hidden and system files as well
- dir /s: displays files in the current directory and all subdirectories

tree: visually shows the child and subdirectories
 
mkdir directory_name: makes a new directory
- rmdir directory_name: removes a directory

_Powershell_

- It combines a command-line interface and a scripting language built on the .NET framework. Unlike older text-based command-line tools, PowerShell is object-oriented, which means it can handle complex data types and interact with system components more effectively. Initially exclusive to Windows

Get-Command: Shows all the possible commands
  - Get-Command -CommandType "insert type": shows a specific type of commands based on the type

Get-Help: Can shows useful information on any command

Get-Alias: Lists all the aliases available

Find-Module: Can find other modules not downloaded and download from the repositories
- Find-Module -Name "Powershell"

Install-Module: Installs module
- Install Module -Name "PowershellGet"

Get-ChildItem: The ls of Powershell
- Get-childitem -path .:\Users: gets the contents of users page
- Get-childitem | Sort-Object Length: gets items then sorts them by length

Set-Location: The cd of Powershell

File editing:
- copy-item
- move-item
- remove-item
- Get-content: view content. The type and cat of powershell

Get-Childitem | Select-Object Name, Length | Sort-Object Length: Will show me only the names and objects and sort by the length size

Select-string: the grep of Powershell. will filter out text patterns within files

Get-localuser: gets all the user accounts

Get-ComputerInfo: like if/ipconfig but better

Get-IPConfiguration: gets IPconfiguration, DNS Servers

Get-Process: Detailed view of ongoing processes, CPU, and memory usage

Get-Service: Retrieval of services that are running, or stopped

Get-NetTCPConnections: shows the open local and remote endpoints. good for looking at holes in systems

Get-Filehash: gets the hash associated with the file, helps verify integrity of files

Get-location ~: go home

Invoke-command: godlike command that can send commands to remove services


**Linux Commands**

curl ipinfo.io: will give my exact IP address
- curl ipinfo.io/IP_address: will give exact location of said address
find .:This initiates the search in the current directory (.) and its subdirectories.

traceroute: discovers the route from your host to the target

-type f:This restricts the search to regular files only, excluding directories, symbolic links, etc.

-size 1033c: This specifies that the file size must be exactly 1033 bytes. The c suffix indicates bytes.

! -executable: This negates the -executable condition, meaning it finds files that are not executable.

-exec file {} +: For each file found that matches the previous criteria, the file command is executed. file determines the type of the file. The {} acts as a placeholder for the found filenames, and + ensures that file processes multiple filenames at once for efficiency.

| grep: used when searching for something specific. a text, a word, anything 
- | grep -w 'text':The output of the file command is piped to grep. grep -w 'text' then filters this output to show only lines containing the whole word "text", which is a common indicator of a human-readable file (e.g., "ASCII text", "UTF-8 Unicode text").
- | grep millionth: Will search for the word millionth 

find /: The command starts a search from the root directory (/), which ensures the entire file system is scanned.

-user: This option filters the search to only include files owned by the user

-group: This option filters the search to only include files owned by the group

 2>/dev/null: This redirects any "Permission denied" error messages to /dev/null (a special file that discards all data written to it). This keeps the output clean and shows only the file you are looking for. 

du -b: check file size

ifconfig: shows IP address, subnet mask, and default gateway

nslookup domainname: looks up the ip address for whatever domain name you insert

netstat: displays the current network connections and listening ports. port 22 = SSH 
- -a: displays all established connections and listening ports
- -b: shos the program associated with each listening port and established connection
- -o reveals the process ID PID associated with the connection
- -n uses a numerical form for addresses and port numbers

dir: view child directories
- dir /a: displays hidden and system files as well
- dir /s: displays files in the current directory and all subdirectories

tree: visually shows the child and subdirectories

mkdir directory_name: makes a new directory
- rmdir directory_name: removes a directory

type: to see the contents of a file

tasklist /: shows the open tasks
- /FI "imagename eq sshd.exe": will show all files with sshd.exe

taskkill /PID: will kill the task associated w/ that PID

chkdsk: checks the file system and disk volumes for error and bad sectors

sfc /scannow: scans system files for corruption and repairs them if possible

shutdown /s: shutdown system
- /r: restart system
- /a: abort system reboot


























