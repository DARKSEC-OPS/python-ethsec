# python-ethsec

Phase 1:

1. Created Github python-ethsec repo

2. Kali Linux Machine: Installed UTM on Mac with Metasploit

**Running nmap -sV -O on MS Target**

<img width="729" height="597" alt="Screenshot 2025-10-11 at 7 06 25 PM" src="https://github.com/user-attachments/assets/1901333f-2efb-47c7-9645-9f15a33deb7c" />


**Master Notes**

**TryHackMe CyberSecurity Foundamentals**

_Types of Browsers_

[Shohan](https://www.shodan.io/): Search engine for browsers connected to internet

[Censys](https://search.censys.io/): Used to search for specifi queries (IP addresses, domains, breaches of security)

[VirusTotal](https://www.virustotal.com/gui/home/upload): Scans files for viruses

[HaveIBeenPwned](https://haveibeenpwned.com/): Shows if an email address has been in a leak (HIBP)

Types of Vulnerabilities and Exploits:

[CVE](urlhttps://www.cve.org/): Common Vulnerabilities and Exploits. Search engine for vulnderabilities

[Exploit Database](https://www.exploit-db.com/): Provides working exploit codes

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


