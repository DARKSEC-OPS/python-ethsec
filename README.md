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


**Linux Commands**

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
