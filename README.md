# python-ethsec

Phase 1:

1. Created Github python-ethsec repo

2. Kali Linux Machine: Installed UTM on Mac with Metasploit

**Running nmap -sV -O on MS Target**

<img width="729" height="597" alt="Screenshot 2025-10-11 at 7 06 25 PM" src="https://github.com/user-attachments/assets/1901333f-2efb-47c7-9645-9f15a33deb7c" />


**Master Notes**

[Internet Hacking 
](https://www.youtube.com/watch?v=dZwbb42pdtg)


**Subnetting (NC) **

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

 When you have the amount of networks needed = hack the bits starting from the left to the right
 When you have the amount of hosts needed = SAVE the bits from right to left and hack the ones left over

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

**Networking Core Protocols**

DNS (Domain Name System): Operates in Application level - layer 7
1. A Record: A address record maps a hostname to one or more IPv4 addresses
2. AAAA Record: Same as A record but for IPv6.
3. CNAME Record: Canonical Name record. Maps a domain name to another domain name. ex - example.com mapped to www.example.com
4. MX Record: Mail exchange record specifies the mail server responsible for handling emails for a domain

HTTP / HTTPS: Hypertext Transfer Protocol (Secure). Uses TCP, typically on port 80 and 443
Common Commands
- GET: Retrieves data from the server (file or image)
- POST: allows us to submit new data to the servier (updloading a file or form)
- PUT: used to create a new resource on the server and to update and overwrite existing information
- DELETE: used to delete a specified file of resource on the server

FTP (File Transfer Protocol): Quicker than HTTP when dealing w/ file transfers. TCP port 21
Common Commands
- USER: used to input the username
- PASS: used to enter the password
- RETR: used to download a file from the FTP server to the client
- STOR: used to upload a file from the client to the FTP server

SMTP (Simple Mail Transfer Protocol): Process in which mail client talks with a mail server and how a mail server talks to one another.  Port 25
Common Commands
- HELO or EHLO: Initiates an SMTP session
- MAIL FROM: specifies the sender's email address
- RCPT TO: specifies the recipient's email address
- DATA: inidiates that the client will begin sending the content of the email message
- . : is sent on a line by itself to indicate the end of the message

POP3 (Post Office Protocol V3): Equivalent to checking your post office for mail sent through SMTP. Port 110
Common Commands
- USER <username> identifies the user
- PASS <password> provides the user’s password
- STAT requests the number of messages and total size
- LIST lists all messages and their sizes
- RETR <message_number> retrieves the specified message
- DELE <message_number> marks a message for deletion
- QUIT ends the POP3 session applying changes, such as deletions

IMAP (Internet Message Access Protocol): allows for synchronization of mailboxes across multiple devices. Port 143
- LOGIN <username> <password> authenticates the user
- SELECT <mailbox> selects the mailbox folder to work with
- FETCH <mail_number> <data_item_name> Example fetch 3 body[] to fetch message number 3, header and body.
- MOVE <sequence_set> <mailbox> moves the specified messages to another mailbox
- COPY <sequence_set> <data_item_name> copies the specified messages to another mailbox
- LOGOUT logs out

**Networking Security Protocols**

TLS (Transport Layer Security): added to existing protocols to protect communication confidentiality, integrity, and authenticity (HTTPS, POP3S, SMTPS, IMAPS)
- Operates in the Transport Layer (4)

SSH (Secure Shell): secure way of accessing remot systems

[Let's Encrypt: Free Security Certificates](https://letsencrypt.org/)

HTTP over TLS = HTTPS: Adds a second step (establishing a TLS session) to the process
1. Establish a TCP three-way handshake with the target server
2. Establish a TLS session
  - Encrypts the content. Only way of accessing is encryption key
     - 
4. Communication using HTTP protocol, for example issuing HTTP request such as GET / HTTP/1.1

Without TLS =
<img width="1033" height="653" alt="image" src="https://github.com/user-attachments/assets/30fe4795-aacc-4736-9433-f3968c814b4c" />

With TLS = 
<img width="1032" height="745" alt="image" src="https://github.com/user-attachments/assets/80585762-23ad-4e83-9caf-f2152ffc2237" />

TCP Ports
<img width="1220" height="742" alt="image" src="https://github.com/user-attachments/assets/a78672d7-749f-42c5-89d5-1638f0ea41b8" />

SSH (Secure Shell) - OpenSSH - Port 22
Benefits:
- Secure authentication: password based and supports public key and two-factor auth
- Confidentiality: end-to-end encryption, protecting against eavesdropping. Provides new server keys to protect against man-in-the-middle attacks
- Integrity: Cryptography protects the integrity of the traffic
- Tunneling: can create a secure "tunnel" to route other protocols through SSH. Leads to VPN-like connection
- X11 Forwarding: allows use of GUI over the network if you connect to a Unix-like system

SFTP (SSH File Transfer Protocol) - Secure file transfer, port 22

FTPS (File Transfer Protocol Secure)

_VPN_

<img width="997" height="672" alt="image" src="https://github.com/user-attachments/assets/d9b7925d-2ad8-4d8c-98cb-7042ccc09459" />

**Wireshark: The Basics**

Wireshark: An open-source tool used to perform pacjet sniffing and investigating live traffic. One of the best packet analysis tools
- used to troubleshoot network problems
- detect security anomalies (rogue hosts, abnormal port usage, and suspicious traffic
- investgate and learn protocol details such as response codes and payload data

Details Pane
- Frame/Packet: Layer1 - Physical Layer of the OSI - shows details
- SOURCE (MAC): Layer 2 - destination MAC Addresses from the Data Link layer of OSI Model
- Souce (IP): Layer 3 - Source and destination IPv4 Addresses; from the Network later of the OSI Model
- Protocol: Layer 4 - details of the UDP/TCP source and destination port. Transport Layer
- Protocol Errors - Continuation of the 4 layer shows specific segements from TCP that needed to be reassembled
- Application Protocol: Layer 5 - details specific to the protocol used (HTTP, FTP, SMB). Application Layer
- Application Data: extension of the 5th layer can show the application-specific data

**[Packet Sniffing - NC](https://www.youtube.com/watch?v=-rSqbgI7oZM&t=638s)**

_Watched Switches and Routers EP1 EP2 for CCNA Course_

Switches and Routers NC 
- Switches = Routers but better. LAYER 2! Data Link
- CISCO packet tracer, provided two little test labs
- Routers = Allow connectivity to different servers. Layer 3! Network

_Methods of capturing traffic_

1. ARP Poisoning (MIM attack - man in the middle attack)
     - Putting yourself in between the router and the destination. Receiving all the traffic
     - Download Wireshark (apt install wireshark)
     - Download nmap (apt install nmap)
     - Download ettercap (apt install ettercap-text-only)
     - 1. Recon: sudonmap -sn <broadcast address>
         - Get this by ip a. And then take the gateway/broadcast address
         - Find desired device
     - 2. sudo ettercap -T -S -i eth0 -M arp:remote (router) /10.0.0.1// /(victim)10.0.0.129//
         - runs attack starts capturing traffic
     - 3. run wireshark (sudo wireshark)
         - filter out only traffic for victim (ip.addr == <ip address>$
     - 4. analyze packets (apackets.com), upload saved pcap file

**Wireshark: Packet Operations**

Comparison Operators: 
<img width="575" height="652" alt="image" src="https://github.com/user-attachments/assets/0443cb60-84d6-4d8b-80e6-04aabb158912" />

IP Filters:
<img width="571" height="699" alt="image" src="https://github.com/user-attachments/assets/bbb5112a-24f7-4ab4-8ed9-43ae72dcffd5" />

**TCPDUMP**

1. Specify the network interface
   - i
   - i any (any interface)
   - i eth0
     ip address show (ip a s): would show the available interfaces

 <img width="1274" height="747" alt="image" src="https://github.com/user-attachments/assets/f54ea50a-ee09-4cd2-8e04-e6bb32f5f3c4" />

 2. Filtering
    - host (host IP, host HOSTNAME)
    - Source Host (src host IP or src host HOSTNAME)
    - Destination (dst host IP or dst host HOSTNAME)
    - Port (port PORT NUMBER)

<img width="861" height="471" alt="image" src="https://github.com/user-attachments/assets/97866688-e580-439b-8aa0-84595cc9a219" />

**NMAP: The Basics: Powerful open source network scanner**
_
NMAP Commands: _

-sn : ping scan (nmap -sn <subnet>)

-PS[portlist]

-PA[portlist]

-PU[portlist]

-sL : confirms who the targets are without scanning. 

-sT : connect scan (tries three way handshake with all ports to check which are open TCP ports. not very stealthy, because it completes the connection (syn, syn-ack, ack)

_-sS : sends a TCP SYN packet. sneakier than a connect scan as it only completes the first part of the handshake. less lows since no connection is established_

_-D : Decoy, creates a decoy IP address to cover your trackes (sudo nmap -sS -D 10.212.12.1 <target IP>_

-sU : scans for UDP services

-F : fast mode. Scans for the 100 most common ports (instead of the default 1000)

-p[range]: allows to specify range (ex. -p10-1024 : scans port 10 - 1024, -p-25 : scans port 1 to 25

-O : OS detection. Let's you know what OS the target is using

-sV : version detection. if we need to gather more information about the target and what services are on that port. Critical when finding the SSH server version **

_-A : is -O, -sV (OS detection, Version scanning, traceroute and more. _

-Pn : scan hosts that appear to be down

-T0 : paranoid (slowest timing 9hrs)

-T1 : sneaky (30 mins)
-T2 : polite (40 sec)
-T3 : normal (.15 sec)
-T4 : aggressive (.13, sec)

-v : verbose - real time scan progress

-d : debugging-level output

-oA : saves on all major formats

-oN : saves on major output

-oX : saves on XML output

-oG L saves a grep-able output (userful for grep and awk)

- Uses multiple ways to discover live hosts
   - IP range using - : scans all the ip addresses from a range (ex. 192.168.0.1 to 192.168.0.10, you can write 192.168.0.1-10)
   - IP subnet using / : scans the subnet (ex. 192.168.0.1/24, and this would be equivalent to 192.168.0.0-255
   - Hostname: can target specifics hostname (ex. example.thm)
   - To show all online hosts -sn (ping scan)
  
 - Ran example of nmap -sn <broadcast address>
   - used ARP request (Address Resolution Protocol - are you up). only used in local networks
   - does not create a lot of noise, just shows the live hosts without discovring what is running on them

_Scanning TCP Ports_
1. Most basic way is to telnet to the ports (TCP - 80, 443)
   - Connect scan is -sT (tries to completed TCP three way handshake with all open TCP ports)
2. Stealthier way is to -sS. Just completes the SYN portion of the three way handshake

_Scanning UDP Ports_
1. Can scan for DNS, DHCP, NTP, SNMP, VoIP
2. nmap offeres -sU to scan for UDP

_Scanning_
1. Find open ports nmap <IP Address>
   - HTTP port will take you to website. 132.212.12.3:8008
 
<img width="1154" height="755" alt="image" src="https://github.com/user-attachments/assets/9922c41d-71d2-429b-82af-3d9d8d65ad9b" />

<img width="1154" height="661" alt="image" src="https://github.com/user-attachments/assets/7770209d-5a07-4893-bfce-91a8f16af216" />

<img width="1152" height="553" alt="image" src="https://github.com/user-attachments/assets/6ad43f73-95d9-49a9-b712-56e48d2aa379" />

_
[NMAP Tutorial to Find Network Vulns - NC](https://www.youtube.com/watch?v=4t4kBkMsDbQ)_

Showing me the open 40, 883 ports (NOT Sneaky -sT): sudo nmap -sT -p 40, 443 192.313.1.0/24
Showing me the open 40, 883 ports (Sneaky -sS): sudo nmap -sT -p 40, 443 192.313.1.0/24

Running a vulnerability scan : sudo nmap --script vuln <target>

**THM: Cryptography**

- Crytography is used to make the connections safe - protects the confidentiality, integrity, and authenticity
- PCI DSS (Payment cared indusctry data security standard): what companies must use to encrypt credit card info

Plaintext (photo, text, etc..) --> Ciphertext --> Key --> Decrypt ---> Plaintext --> Receipient

Ceasar Cipher: oldest most simple cipher
- shifting each key to the right by a certain number
- Ex: TRYHACKME, Key 3 (right)
   - Cipher: WUBKDFNPH
   - Decryption: Shift to the left
 
 Symmetric Encryption: using the same key to encrypt and decrypt
 Asymmetric Encryption: Uses a pair of keys. One to encrypt and the other to decript

 Authentication: Making sure you're communicating with the right person
 Authenticity: Making sure that you can verify the incformation is coming from the claimed source
 Integrity: Ensuring that no one changes the data you exchange
 Confidentiality: Preventing an unauthorized party from eavesdropping on your conversations

Secret code = Symmetric Encryption Cipher and Key
Lock = Public Key
Lock's Key = Private Key

RSA Key (public-key encryption, asymmetric): Multiplying two large prime numbers
- comes up during Capture the Flags
- 
    p and q are large prime numbers
    n is the product of p and q
    The public key is n and e
    The private key is n and d
    m is used to represent the original message, i.e., plaintext
    c represents the encrypted text, i.e., ciphertext

- [RSACTFTOOL](https://github.com/RsaCtfTool/RsaCtfTool)

Diffie-Hellman Key Exchange: Establishing a shared secret between two parties

<img width="966" height="714" alt="image" src="https://github.com/user-attachments/assets/9f8c8aff-758f-48b4-be18-731c2146276b" />

PGP = Pretty Good Privacy
- software that implements encryption for encrypting files, digital signing and more.
- GnuPG or GPG is an open-source implementation of the OpenPGP standard

GPG = Used to protect confidentiality of email messages
- Need to decrypt files in CTFs
- to import key: gpg --import backup.key
- to decrypt messages: gpg --decrypt confidential_message.gpg

**THM: Hashing Basics**

Hash values: fixed-size string or characters that is computed by a hash function. 
Hash function: takes an input of an arbitrary size and returns an output of fixed length. ie - a hash value

Different types of hashes
- hexdump -C
- md5sum
- sha1sum
- sha256sum

Insecure Passwords
- Plaintext
   - rockyou.txt = company that developed social media apps and widgets, had a breach, stored their passwords in plaintext, contains over 14 million passwords
- Insecure encryption algorithm
- Insecure hash function

Linux - Hashes are stored in /etc/shadow ; only readable by root
The encrypted password field contains the hashed passphrase with four components: prefix (algorithm id), options (parameters), salt, and hash. It is saved in the format $prefix$options$salt$hash

Hash Types: https://hashcat.net/wiki/doku.php?id=example_hashes

_Cracking Hashes_

Use hashcat to crack the hash, $2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG, saved in ~/Hashing-Basics/Task-6/hash1.txt.       hashcat -m 3200 -a 0 ~/Hashing-Basics/Task-6/hash1.txt rockyou.txt

Use hashcat to crack the SHA2-256 hash, 9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1, saved in saved in ~/Hashing-Basics/Task-6/hash2.txt.
  hashcat -m 1400 -a 0 hash2.txt ~/rockyou.txt

Use hashcat to crack the hash, $6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0, saved in ~/Hashing-Basics/Task-6/hash3.txt.
  hashcat -m 1800 -a 0 hash3.txt ~/rockyou.txt

**John the Ripper**

[Hask Identifier](https://hashes.com/en/tools/hash_identifier)

john [options] [file path]
    john: Invokes the John the Ripper program
    [options]: Specifies the options you want to use
    [file path]: The file containing the hash you’re trying to crack; if it’s in the same directory, you won’t need to name a path, just the file.

Once you have identified the hash that you’re dealing with, you can tell John to use it while cracking the provided hash using the following syntax:

john --format=[format] --wordlist=[path to wordlist] [path to file]

    --format=: This is the flag to tell John that you’re giving it a hash of a specific format and to use the following format to crack it
    [format]: The format that the hash is in

Example: john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt

ntlm.txt = --format needs to change to --format=NT

Single Crack Mode: john --single --format=raw-sha256 hashes.txt
- note: make sure to add the user name to the hash before running John

Cracking password protected ZIP files:

zip2john [options] [zip file] > [output file]

    [options]: Allows you to pass specific checksum options to zip2john; this shouldn’t often be necessary
    [zip file]: The path to the Zip file you wish to get the hash of
    >: This redirects the output from this command to another file
    [output file]: This is the file that will store the output

  Example: zip2john zipfile.zip > zip_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt

Cracking Rar2John Files

rar2john [rar file] > [output file]

    rar2john: Invokes the rar2john tool
    [rar file]: The path to the RAR file you wish to get the hash of
    >: This redirects the output of this command to another file
    [output file]: This is the file that will store the output from the command

SSH2John - used to hack SSH files
ssh2john [id_rsa private key file] > [output file]

    ssh2john: Invokes the ssh2john tool
    [id_rsa private key file]: The path to the id_rsa file you wish to get the hash of
    >: This is the output director. We’re using it to redirect the output from this command to another file.
    [output file]: This is the file that will store the output from


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

dig a <hostname>: find the IP address associated with a domain name

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

python3 hash-id py: launches the hash identifier on kali

man 5 crypt: detials about the different password prefixes

ssh-keygen: generate an SSH key pair
1. ssh -i privateKeyFileName user@host
2. chmod 600 gives read and write permission
  
curl ipinfo.io: will give my exact IP address
- curl ipinfo.io/IP_address: will give exact location of said address
find .:This initiates the search in the current directory (.) and its subdirectories.

traceroute: discovers the route from your host to the target

-type f:This restricts the search to regular files only, excluding directories, symbolic links, etc.

telnet <IP Address>: connects to a website 
- GET / file.html: gets a specific file on that page

ftp <IP address>: access the file transfer server on a website. Make sure you change to type ASCII before getting

sftp username@hostname: secure file transfer

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

dig a <hostname>: find the IP address associated with a domain name

nc <IP Address> 80: creates a network connection for reading and writing messages

whois: looks up the file on the WHOIS website, which has the details of who registered the domain. Public information

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


























