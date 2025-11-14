document.addEventListener('DOMContentLoaded', () => {
    
    // --- 1. COMPTIA SY0-701 ABBREVIATIONS (COMPLETE LIST) ---
    const terms = [
        { term: "2FA", definition: "Two-factor Authentication", explanation: "Requires two different types of credentials (e.g., a password + a phone code) to log in." },
        { term: "3DES", definition: "Triple Data Encryption Standard", explanation: "An older, slower symmetric encryption. It's now considered weak and replaced by AES." },
        { term: "AAA", definition: "Authentication, Authorization, and Accounting", explanation: "A core security framework. Proves who you are (AuthN), controls what you can do (AuthZ), and logs what you did (Accounting)." },
        { term: "ACL", definition: "Access Control List", explanation: "A list of rules, typically on a firewall or router, that defines what traffic is allowed or denied." },
        { term: "AES", definition: "Advanced Encryption Standard", explanation: "The modern, fast, and strong symmetric encryption standard used worldwide. It replaced DES." },
        { term: "AES-256", definition: "Advanced Encryption Standards 256-bit", explanation: "The 256-bit key version of AES. It's the strongest and most common variant, approved for top-secret data." },
        { term: "AH", definition: "Authentication Header", explanation: "Part of the IPSec protocol suite. It provides integrity and authentication, but no encryption (that's ESP's job)." },
        { term: "AI", definition: "Artificial Intelligence", explanation: "Computer systems that perform tasks normally requiring human intelligence. In security, used for threat analysis and behavior spotting." },
        { term: "AIS", definition: "Automated Indicator Sharing", explanation: "A standard for sharing Indicators of Compromise (IoCs) like malicious IPs or file hashes between organizations." },
        { term: "ALE", definition: "Annualized Loss Expectancy", explanation: "A risk calculation formula: ALE = SLE  ARO. It tells you exactly how much money you can expect to lose per year." },
        { term: "AP", definition: "Access Point", explanation: "A hardware device (like a router) that allows wireless (Wi-Fi) devices to connect to a wired network." },
        { term: "API", definition: "Application Programming Interface", explanation: "A set of rules that allows different software applications to communicate with each other. Securing APIs is critical." },
        { term: "APT", definition: "Advanced Persistent Threat", explanation: "A highly skilled, well-funded attacker (like a nation-state) that gains unauthorized access and stays hidden for a long time." },
        { term: "ARO", definition: "Annualized Rate of Occurrence", explanation: "A risk calculation. It's the number of times you expect a specific threat (like a server failure) to occur in one year." },
        { term: "ARP", definition: "Address Resolution Protocol", explanation: "Resolves an IP address to a physical MAC address on a local network. Vulnerable to 'ARP poisoning' attacks." },
        { term: "ASLR", definition: "Address Space Layout Randomization", explanation: "A memory-protection technique that makes buffer overflow attacks harder by randomly arranging program memory addresses." },
        { term: "ATT&CK", definition: "Adversarial Tactics, Techniques, and Common Knowledge", explanation: "A knowledge base from MITRE that documents and categorizes real-world attacker behaviors." },
        { term: "AUP", definition: "Acceptable Use Policy", explanation: "The document you sign at work or school that defines what you are and are not allowed to do on the network." },
        { term: "AV", definition: "Antivirus", explanation: "Software designed to detect, prevent, and remove malware (malicious software)." },
        { term: "BASH", definition: "Bourne Again Shell", explanation: "The default command-line interface (shell) for most Linux and macOS systems." },
        { term: "BCP", definition: "Business Continuity Planning", explanation: "The proactive plan for how a business will continue to operate during and after a disaster. The BIA is the first step." },
        { term: "BGP", definition: "Border Gateway Protocol", explanation: "The routing protocol of the internet. It exchanges routing information between large, separate networks (Autonomous Systems)." },
        { term: "BIA", definition: "Business Impact Analysis", explanation: "The first step in BCP. It identifies critical business functions, their recovery time (RTO/RPO), and the impact of their failure." },
        { term: "BIOS", definition: "Basic Input/Output System", explanation: "The old-style firmware used to boot a computer. It's now been replaced by the more secure UEFI." },
        { term: "BPA", definition: "Business Partners Agreement", explanation: "A legal agreement between two business partners that defines roles, responsibilities, and data sharing rules." },
        { term: "BPDU", definition: "Bridge Protocol Data Unit", explanation: "Packets used by network switches to prevent network loops (Spanning Tree Protocol). 'BPDU Guard' is a security feature." },
        { term: "BYOD", definition: "Bring Your Own Device", explanation: "A policy allowing employees to use their personal devices (phones, laptops) for work. Creates security challenges." },
        { term: "CA", definition: "Certificate Authority", explanation: "A trusted entity (like Let's Encrypt) that issues and signs digital certificates as part of the Public Key Infrastructure (PKI)." },
        { term: "CAPTCHA", definition: "Completely Automated Public Turing Test to Tell Computers and Humans Apart", explanation: "The 'I am not a robot' test. It's used to prevent automated bots from abusing a website." },
        { term: "CAR", definition: "Corrective Action Report", explanation: "A document used in incident response that details the steps taken to fix a problem and prevent it from happening again." },
        { term: "CASB", definition: "Cloud Access Security Broker", explanation: "A security tool that sits between users and cloud services to enforce security policies and monitor activity." },
        { term: "CBC", definition: "Cipher Block Chaining", explanation: "A common mode of operation for block ciphers. It chains blocks together, so each block's encryption depends on the one before it." },
        { term: "CCMP", definition: "Counter Mode/CBC-MAC Protocol", explanation: "The modern encryption protocol used in WPA2 and WPA3 to secure Wi-Fi networks. It's much stronger than TKIP." },
        { term: "CCTV", definition: "Closed-circuit Television", explanation: "A set of cameras used for physical security surveillance, where the signal is not publicly broadcast." },
        { term: "CERT", definition: "Computer Emergency Response Team", explanation: "A team of experts that handles computer security incidents. Also known as a CIRT or CSIRT." },
        { term: "CFB", definition: "Cipher Feedback", explanation: "A mode for block ciphers that allows them to function like a stream cipher, encrypting smaller units of data." },
        { term: "CHAP", definition: "Challenge Handshake Authentication Protocol", explanation: "An authentication protocol that verifies a user without sending the actual password over the network." },
        { term: "CIA", definition: "Confidentiality, Integrity, Availability", explanation: "The 'CIA Triad,' the three core principles of information security. (Keep secrets, prevent tampering, ensure access)." },
        { term: "CIO", definition: "Chief Information Officer", explanation: "The C-level executive responsible for all IT strategy and management within an organization." },
        { term: "CIRT", definition: "Computer Incident Response Team", explanation: "Same as a CERT. This is the team that responds to cybersecurity incidents like hacks or malware outbreaks." },
        { term: "CMS", definition: "Content Management System", explanation: "A platform like WordPress or Joomla used to build and manage websites. A common target for attackers." },
        { term: "COBO", definition: "Corporate-owned, Business-only", explanation: "A strict mobile device model where the company owns the device and it can only be used for work." },
        { term: "COOP", definition: "Continuity of Operation Planning", explanation: "A BCP (Business Continuity Plan) specifically for government agencies, ensuring essential services can continue." },
        { term: "COPE", definition: "Corporate Owned, Personally Enabled", explanation: "A mobile device model where the company owns the device, but employees are allowed some personal use." },
        { term: "CP", definition: "Contingency Planning", explanation: "The overall process of preparing for an unexpected event, which includes BCP, DRP, and IR plans." },
        { term: "CRC", definition: "Cyclical Redundancy Check", explanation: "An error-checking technique used to verify data integrity (to see if data was corrupted, not if it was tampered with)." },
        { term: "CRL", definition: "Certificate Revocation List", explanation: "A 'blacklist' published by a Certificate Authority (CA). It lists all digital certificates that have been revoked." },
        { term: "CSO", definition: "Chief Security Officer", explanation: "The C-level executive responsible for an organization's total security (both physical and digital)." },
        { term: "CSP", definition: "Cloud Service Provider", explanation: "A company that provides cloud computing services, like Amazon (AWS), Microsoft (Azure), or Google (GCP)." },
        { term: "CSR", definition: "Certificate Signing Request", explanation: "A message you send to a Certificate Authority (CA) to request a new digital certificate for your server." },
        { term: "CSRF", definition: "Cross-site Request Forgery", explanation: "An attack that tricks a user's browser into sending an unauthorized command to a website they're already logged into." },
        { term: "CSU", definition: "Channel Service Unit", explanation: "A hardware device that connects a LAN to a WAN, like a T1 line. It's an older-style networking component." },
        { term: "CTM", definition: "Counter Mode", explanation: "A fast, modern encryption mode (like AES-CTM) that turns a block cipher into a stream cipher. Often used with GCM." },
        { term: "CTO", definition: "Chief Technology Officer", explanation: "The C-level executive focused on future technology, R&D, and implementing new tech strategies." },
        { term: "CVE", definition: "Common Vulnerability Enumeration", explanation: "A public list of all known cybersecurity vulnerabilities. Each one gets a unique `CVE-YYYY-NNNN` number." },
        { term: "CVSS", definition: "Common Vulnerability Scoring System", explanation: "A public, standardized scoring system (0-10) that rates the severity of a vulnerability." },
        { term: "CYOD", definition: "Choose Your Own Device", explanation: "A mobile device policy where the company provides a list of approved devices, and the employee can pick one." },
        { term: "DAC", definition: "Discretionary Access Control", explanation: "An access control model where the owner of a file or resource gets to decide (at their 'discretion') who can access it." },
        { term: "DBA", definition: "Database Administrator", explanation: "The person responsible for designing, managing, and securing a company's databases." },
        { term: "DDoS", definition: "Distributed Denial of Service", explanation: "A DoS attack launched from many different computers (a botnet) to overwhelm a target with traffic." },
        { term: "DEP", definition: "Data Execution Prevention", explanation: "A security feature that marks areas of memory as 'non-executable,' preventing buffer overflow attacks from running code." },
        { term: "DES", definition: "Digital Encryption Standard", explanation: "An old, weak symmetric encryption standard with a 56-bit key. It is fully broken and replaced by AES." },
        { term: "DHCP", definition: "Dynamic Host Configuration Protocol", explanation: "The network service that automatically assigns IP addresses to devices when they join a network." },
        { term: "DHE", definition: "Diffie-Hellman Ephemeral", explanation: "A key exchange algorithm that uses temporary (ephemeral) keys. This provides Perfect Forward Secrecy (PFS)." },
        { term: "DKIM", definition: "DomainKeys Identified Mail", explanation: "An email security standard that uses a digital signature to prove that an email really came from the domain it claims to." },
        { term: "DLL", definition: "Dynamic Link Library", explanation: "A file containing code and data that can be shared by multiple programs on Windows. 'DLL hijacking' is an attack." },
        { term: "DLP", definition: "Data Loss Prevention", explanation: "Software or hardware that scans network traffic and endpoints to prevent sensitive data (like PII) from being leaked." },
        { term: "DMARC", definition: "Domain Message Authentication Reporting and Conformance", explanation: "An email security standard that builds on SPF and DKIM. It tells a receiving server what to do with a failed email (reject/quarantine)." },
        { term: "DNAT", definition: "Destination Network Address Translation", explanation: "A technique used by firewalls to change the destination IP of a packet (e.g., port forwarding)." },
        { term: "DNS", definition: "Domain Name System", explanation: "The 'phonebook of the internet.' It translates human-readable names (like `google.com`) into computer-readable IP addresses." },
        { term: "DNSSEC", definition: "Domain Name System Security Extensions", explanation: "The secure version of DNS. It uses digital signatures to guarantee that the DNS response is authentic and not tampered with." },
        { term: "DoS", definition: "Denial of Service", explanation: "An attack designed to shut down a machine or network, making it inaccessible to its intended users (e.g., a SYN flood)." },
        { term: "DPO", definition: "Data Privacy Officer", explanation: "A corporate leadership role required by GDPR, responsible for overseeing all data protection and privacy policies." },
        { term: "DRP", definition: "Disaster Recovery Plan", explanation: "The plan for how to recover IT infrastructure (servers, data) after a disaster. Part of the larger BCP." },
        { term: "DSA", definition: "Digital Signature Algorithm", explanation: "An algorithm used to create digital signatures, which provide authentication, integrity, and non-repudiation." },
        { term: "DSL", definition: "Digital Subscriber Line", explanation: "A common type of internet connection that provides broadband access over standard telephone lines." },
        { term: "EAP", definition: "Extensible Authentication Protocol", explanation: "An authentication framework, not a single protocol. It's used in 802.1X and WPA2/3 to allow different auth methods." },
        { term: "ECB", definition: "Electronic Code Book", explanation: "The weakest and simplest mode for a block cipher. It's weak because the same input always produces the same output." },
        { term: "ECC", definition: "Elliptic Curve Cryptography", explanation: "A type of public-key cryptography that creates very strong keys with smaller key sizes. Ideal for mobile devices." },
        { term: "ECDHE", definition: "Elliptic Curve Diffie-Hellman Ephemeral", explanation: "A key exchange algorithm that combines ECC (for small keys) and Ephemeral (for PFS). Very common in modern TLS." },
        { term: "ECDSA", definition: "Elliptic Curve Digital Signature Algorithm", explanation: "The Elliptic Curve version of DSA. It creates faster, smaller, but equally strong digital signatures." },
        { term: "EDR", definition: "Endpoint Detection and Response", explanation: "An advanced version of antivirus. It monitors endpoints (laptops, servers) for threats and helps security teams respond." },
        { term: "EFS", definition: "Encrypted File System", explanation: "A feature built into Windows that allows you to encrypt individual files and folders at the file-system level." },
        { term: "ERP", definition: "Enterprise Resource Planning", explanation: "A large, centralized software suite that manages all of a company's main business processes (HR, finance, supply chain)." },
        { term: "ESN", definition: "Electronic Serial Number", explanation: "An older, unique identification number for a mobile phone. Has been largely replaced by IMEI." },
        { term: "ESP", definition: "Encapsulated Security Payload", explanation: "Part of the IPSec protocol suite. It provides encryption and confidentiality, as well as authentication and integrity." },
        { term: "EULA", definition: "End User License Agreement", explanation: "The legal contract you click 'I Agree' to when you install new software." },
        { term: "FACL", definition: "File System Access Control List", explanation: "A standard ACL (Access Control List) but applied specifically to files and folders in a file system." },
        { term: "FDE", definition: "Full Disk Encryption", explanation: "Encryption that automatically encrypts the entire hard drive, including the OS. (e.g., BitLocker, FileVault)." },
        { term: "FIM", definition: "File Integrity Management", explanation: "Software that monitors important system files and logs to see if they have been tampered with. (e.g., Tripwire)." },
        { term: "FPGA", definition: "Field Programmable Gate Array", explanation: "A type of computer chip that can be re-programmed after it's been manufactured. Used for specialized, high-speed tasks." },
        { term: "FRR", definition: "False Rejection Rate", explanation: "A biometric security error. It's the percentage of times a legitimate user is incorrectly denied access. (Type I error)." },
        { term: "FTP", definition: "File Transfer Protocol", explanation: "An insecure protocol for transferring files. It sends all data, including passwords, in clear text. Use FTPS or SFTP instead." },
        { term: "FTPS", definition: "Secured File Transfer Protocol", explanation: "FTP secured with SSL/TLS. It's one secure way to transfer files (do not confuse with SFTP)." },
        { term: "GCM", definition: "Galois Counter Mode", explanation: "A modern, fast, and secure mode for symmetric ciphers (like AES). It provides both encryption and authentication (AEAD)." },
        { term: "GDPR", definition: "General Data Protection Regulation", explanation: "A strict data privacy law from the EU. It gives individuals control over their personal data and applies to any company worldwide." },
        { term: "GPG", definition: "Gnu Privacy Guard", explanation: "A popular, free, and open-source version of PGP (Pretty Good Privacy) used for encrypting emails and files." },
        { term: "GPO", definition: "Group Policy Object", explanation: "In Windows Active Directory, this is a set of rules and policies (e.g., 'disable USB drives') that can be applied to many users/computers." },
        { term: "GPS", definition: "Global Positioning System", explanation: "A satellite-based system for geolocation. A security risk related to tracking and location privacy." },
        { term: "GPU", definition: "Graphics Processing Unit", explanation: "The chip that handles graphics. Also used by attackers for password cracking because it can perform hashes very quickly." },
        { term: "GRE", definition: "Generic Routing Encapsulation", explanation: "A tunneling protocol that can wrap many different types of network protocols inside IP packets. Often used with VPNs." },
        { term: "HA", definition: "High Availability", explanation: "A system design that ensures a service is always available by eliminating single points of failure (e.g., clustering, load balancing)." },
        { term: "HDD", definition: "Hard Disk Drive", explanation: "A traditional, mechanical storage device that uses spinning magnetic disks. Slower and less reliable than an SSD." },
        { term: "HIDS", definition: "Host-based Intrusion Detection System", explanation: "An IDS that is installed on a single computer (a host) to monitor its logs, system files, and network traffic." },
        { term: "HIPS", definition: "Host-based Intrusion Prevention System", explanation: "A HIDS that can also block suspected attacks on the host, not just log them." },
        { term: "HMAC", definition: "Hashed Message Authentication Code", explanation: "A hash (for integrity) combined with a secret key (for authentication). It proves a message is from the right sender and wasn't changed." },
        { term: "HOTP", definition: "HMAC-based One-time Password", explanation: "An algorithm for generating one-time passwords, often based on a counter (i.e., you press the button on a token)." },
        { term: "HSM", definition: "Hardware Security Module", explanation: "A special, tamper-proof hardware device that securely stores and manages digital keys. Very high security." },
        { term: "HTML", definition: "Hypertext Markup Language", explanation: "The standard language used to create and structure the content of web pages." },
        { term: "HTTP", definition: "Hypertext Transfer Protocol", explanation: "The insecure protocol used by web browsers to communicate with web servers. All data is sent in clear text." },
        { term: "HTTPS", definition: "Hypertext Transfer Protocol Secure", explanation: "The secure version of HTTP. It uses SSL/TLS to encrypt all communication, indicated by the 'padlock' icon." },
        { term: "HVAC", definition: "Heating, Ventilation Air Conditioning", explanation: "Part of a building's physical/environmental security. Used to control temperature and humidity in a data center." },
        { term: "IaaS", definition: "Infrastructure as a Service", explanation: "A cloud model where the provider rents out the basic infrastructure (VMs, storage, network). You manage the OS and apps." },
        { term: "IaC", definition: "Infrastructure as Code", explanation: "The process of managing and provisioning data centers through machine-readable definition files (scripts), rather than manually." },
        { term: "IAM", definition: "Identity and Access Management", explanation: "The security discipline that manages who has what access to which resources (e.g., user provisioning, RBAC)." },
        { term: "ICMP", definition: "Internet Control Message Protocol", explanation: "A network protocol used for diagnostics (e.g., `ping`). Can be used in attacks like a 'ping flood' or 'ping of death'." },
        { term: "ICS", definition: "Industrial Control Systems", explanation: "General term for computer systems that control industrial processes (e.g., power plants, manufacturing). Part of OT." },
        { term: "IDEA", definition: "International Data Encryption Algorithm", explanation: "An older symmetric block cipher. Not as common as AES." },
        { term: "IDF", definition: "Intermediate Distribution Frame", explanation: "A network closet that connects the MDF (main closet) to the wall jacks and workstations on a single floor." },
        { term: "IdP", definition: "Identity Provider", explanation: "In federated identity (like SSO), this is the service that stores and authenticates the user's identity (e.g., Google, Okta)." },
        { term: "IDS", definition: "Intrusion Detection System", explanation: "A security device that monitors network traffic or a host for suspicious activity and sends an alert. It only detects, it doesn't block." },
        { term: "IEEE", definition: "Institute of Electrical and Electronics Engineers", explanation: "A professional organization that creates many common standards, such as 802.11 (Wi-Fi) and 802.3 (Ethernet)." },
        { term: "IKE", definition: "Internet Key Exchange", explanation: "The protocol used in IPSec to negotiate and set up a secure, encrypted connection (a Security Association)." },
        { term: "IM", definition: "Instant Messaging", explanation: "Real-time text communication (e.g., WhatsApp, Signal). Can be a data-leakage risk if not encrypted." },
        { term: "IMAP", definition: "Internet Message Access Protocol", explanation: "A protocol for receiving email (like POP). It syncs emails with the server, so you see the same inbox on all devices." },
        { term: "IoC", definition: "Indicators of Compromise", explanation: "Evidence that a security breach has occurred (e.g., a malicious IP, a strange filename, a weird login pattern)." },
        { term: "IoT", definition: "Internet of Things", explanation: "Physical devices (like smart toasters, cameras, thermostats) that are connected to the internet. Often very insecure." },
        { term: "IP", definition: "Internet Protocol", explanation: "The main protocol for routing packets across the internet. It provides the addressing (IP address) for devices." },
        { term: "IPS", definition: "Intrusion Prevention System", explanation: "An IDS that can also block suspected attacks in real-time. It 'prevents' the attack, while an IDS only 'detects' it." },
        { term: "IPSec", definition: "Internet Protocol Security", explanation: "A secure network protocol suite that encrypts traffic at the IP level. Used to create many VPNs. (Uses AH and ESP)." },
        { term: "IR", definition: "Incident Response", explanation: "The process and set of procedures for handling a security breach, from detection and containment to recovery and lessons learned." },
        { term: "IRC", definition: "Internet Relay Chat", explanation: "An older text-based chat system. Still used by some technical communities and by attackers for C2 (Command & Control)." },
        { term: "IRP", definition: "Incident Response Plan", explanation: "The formal, written document that outlines all the steps to take during and after a security incident (IR)." },
        { term: "ISO", definition: "International Standards Organization", explanation: "A worldwide body that develops and publishes standards, including the ISO 27000 series for information security." },
        { term: "ISP", definition: "Internet Service Provider", explanation: "The company you pay for internet access (e.g., Comcast, AT&T)." },
        { term: "ISSO", definition: "Information Systems Security Officer", explanation: "A job role responsible for implementing and maintaining security policies for a specific system or department." },
        { term: "IV", definition: "Initialization Vector", explanation: "A random number used with an encryption key to ensure that the same plaintext doesn't encrypt to the same ciphertext twice." },
        { term: "KDC", definition: "Key Distribution Center", explanation: "A core component in Kerberos authentication. It's the server that issues tickets (TGT, TGS) to users." },
        { term: "KEK", definition: "Key Encryption Key", explanation: "A key that is used solely to encrypt (wrap) other keys. This protects the data-encrypting keys when they're stored." },
        { term: "L2TP", definition: "Layer 2 Tunneling Protocol", explanation: "A VPN tunneling protocol. It does not provide encryption itself, so it's almost always bundled with IPSec." },
        { term: "LAN", definition: "Local Area Network", explanation: "A computer network confined to a small area, like a single office building or a home." },
        { term: "LDAP", definition: "Lightweight Directory Access Protocol", explanation: "A protocol used to query and modify directory services, such as Microsoft Active Directory." },
        { term: "LEAP", definition: "Lightweight Extensible Authentication Protocol", explanation: "A Cisco-proprietary, older version of EAP. It's insecure and should not be used." },
        { term: "MaaS", definition: "Monitoring as a Service", explanation: "A cloud service model where the provider offers a monitoring platform (for logs, network, etc.) to the customer." },
        { term: "MAC", definition: "Mandatory Access Control / Media Access Control / Message Authentication Code", explanation: "1) A strict, rule-based access model (vs. DAC). 2) A unique hardware address on a NIC. 3) A hash with a secret key to verify integrity and authenticity." },
        { term: "MAN", definition: "Metropolitan Area Network", explanation: "A computer network that covers a geographic area larger than a LAN but smaller than a WAN, like a city." },
        { term: "MBR", definition: "Master Boot Record", explanation: "The boot sector of a hard drive in the older BIOS system. 'Bootkit' malware often targets the MBR." },
        { term: "MD5", definition: "Message Digest 5", explanation: "An old hashing algorithm that produces a 128-bit hash. It's now 'broken' (prone to collisions) and should only be used for integrity checks, not security." },
        { term: "MDF", definition: "Main Distribution Frame", explanation: "The primary wiring closet in a building. It's the central point for all network cabling, connecting to IDFs and the outside world." },
        { term: "MDM", definition: "Mobile Device Management", explanation: "Software used to manage and secure mobile devices (phones, tablets), especially in a BYOD environment." },
        { term: "MFA", definition: "Multifactor Authentication", explanation: "A secure authentication method that requires two or more factors (e.g., something you know, have, or are)." },
        { term: "MFD", definition: "Multifunction Device", explanation: "A single device that does many things, like a printer/scanner/fax machine. A security risk because it has a hard drive and network access." },
        { term: "MFP", definition: "Multifunction Printer", explanation: "Another name for an MFD (Multifunction Device)." },
        { term: "ML", definition: "Machine Learning", explanation: "A subset of AI where a system 'learns' from data to identify patterns. Used in security to detect anomalies and new malware." },
        { term: "MMS", definition: "Multimedia Message Service", explanation: "The standard for sending text messages that include pictures, video, or audio." },
        { term: "MOA", definition: "Memorandum of Agreement", explanation: "A formal document outlining a cooperative agreement between two or more parties, often involving payment or action." },
        { term: "MOU", definition: "Memorandum of Understanding", explanation: "A less formal document than an MOA. It expresses a 'handshake' agreement and a common line of action, usually not legally binding." },
        { term: "MPLS", definition: "Multi-protocol Label Switching", explanation: "A fast, private networking technology used by ISPs to create dedicated WAN connections for businesses. It's a 'leased line' alternative." },
        { term: "MSA", definition: "Master Service Agreement", explanation: "A main, overarching legal contract that governs all future transactions or agreements between two parties." },
        { term: "MSCHAP", definition: "Microsoft Challenge Handshake Authentication Protocol", explanation: "A Microsoft-proprietary version of CHAP. MSCHAPv2 is the current version, but it's still considered weak." },
        { term: "MSP", definition: "Managed Service Provider", explanation: "An IT company that you outsource your day-to-day IT management to (e.g., helpdesk, network management)." },
        { term: "MSSP", definition: "Managed Security Service Provider", explanation: "An MSP that specializes in security. You outsource your SOC, firewall management, or monitoring to them." },
        { term: "MTBF", definition: "Mean Time Between Failures", explanation: "A reliability metric for repairable items. It's the average time a device works before it breaks down." },
        { term: "MTTF", definition: "Mean Time to Failure", explanation: "A reliability metric for non-repairable items (like a lightbulb). It's the average lifespan of a device." },
        { term: "MTTR", definition: "Mean Time to Recover", explanation: "The average time it takes to repair a failed system and get it back online. A key metric in BCP/DRP." },
        { term: "MTU", definition: "Maximum Transmission Unit", explanation: "The largest packet size (in bytes) that can be sent over a specific network. Can be used in 'fragmentation' attacks." },
        { term: "NAC", definition: "Network Access Control", explanation: "A security solution that inspects devices before they're allowed on the network. It checks for compliance (e.g., AV, updates) and can quarantine them." },
        { term: "NAT", definition: "Network Address Translation", explanation: "The technology (usually on a router) that allows many devices on a private network (192.168.x.x) to share a single public IP address." },
        { term: "NDA", definition: "Non-disclosure Agreement", explanation: "A legal contract that prevents you from sharing confidential information you learn as part of a job or project." },
        { term: "NFC", definition: "Near Field Communication", explanation: "A very short-range wireless technology (e.g., Apple Pay, Google Pay). Can be used in 'eavesdropping' attacks." },
        { term: "NGFW", definition: "Next-generation Firewall", explanation: "An 'application-aware' firewall. It goes beyond just ports/IPs (like a WAF) and can inspect application-layer (Layer 7) traffic." },
        { term: "NIDS", definition: "Network-based Intrusion Detection System", explanation: "An IDS that monitors traffic for an entire network segment. It's 'promiscuous' and listens to all traffic." },
        { term: "NIPS", definition: "Network-based Intrusion Prevention System", explanation: "A NIDS that is placed inline with network traffic so it can block attacks for the whole network, not just detect them." },
        { term: "NIST", definition: "National Institute of Standards & Technology", explanation: "A U.S. agency that creates many security standards, including the NIST Cybersecurity Framework (CSF) and SP 800-53." },
        { term: "NTFS", definition: "New Technology File System", explanation: "The standard, modern file system for Windows. Its key security feature is that it supports granular file and folder permissions (ACLs)." },
        { term: "NTLM", definition: "New Technology LAN Manager", explanation: "An older, weak Microsoft authentication protocol. It's been replaced by Kerberos but is often still enabled for compatibility." },
        { term: "NTP", definition: "Network Time Protocol", explanation: "The protocol used to synchronize clocks on computers and network devices. Crucial for accurate log correlation." },
        { term: "OAUTH", definition: "Open Authorization", explanation: "An authorization framework. It's what lets you 'Log in with Google/Facebook' to grant one app delegated access to your data on another app." },
        { term: "OCSP", definition: "Online Certificate Status Protocol", explanation: "A faster way to check if a single digital certificate is valid. It's an online query that replaces downloading a big CRL." },
        { term: "OID", definition: "Object Identifier", explanation: "A unique string of numbers used to identify objects, like policies or attributes, within a digital certificate." },
        { term: "OS", definition: "Operating System", explanation: "The core software that manages a computer's hardware and resources (e.g., Windows, Linux, macOS, Android)." },
        { term: "OSINT", definition: "Open-source Intelligence", explanation: "Intelligence gathering using publicly available sources (e.g., social media, Google, public records). The first step in a pentest." },
        { term: "OSPF", definition: "Open Shortest Path First", explanation: "An internal routing protocol used inside a large network (an AS) to determine the best path for traffic." },
        { term: "OT", definition: "Operational Technology", explanation: "The hardware and software used to control physical industrial processes (e.g., ICS, SCADA). Contrasted with IT (Information Tech)." },
        { term: "OTA", definition: "Over the Air", explanation: "Updates (for firmware, software) that are sent wirelessly to devices like smartphones or IoT devices." },
        { term: "OVAL", definition: "Open Vulnerability Assessment Language", explanation: "A standardized XML language used to define and check for specific vulnerabilities or system configurations." },
        { term: "P12", definition: "PKCS #12", explanation: "A file format used to store a digital certificate and its private key in a single, password-protected file. (Often has a .p12 or .pfx extension)." },
        { term: "P2P", definition: "Peer to Peer", explanation: "A decentralized network model where all devices (peers) share resources with each other, without a central server (e.g., BitTorrent)." },
        { term: "PaaS", definition: "Platform as a Service", explanation: "A cloud model where the provider gives you the platform (OS, web server, database). You just manage your code and data." },
        { term: "PAC", definition: "Proxy Auto Configuration", explanation: "A file (a small script) that tells a web browser which proxy server to use for a given URL." },
        { term: "PAM", definition: "Privileged Access Management", explanation: "A security solution to control, monitor, and audit all 'privileged' accounts (like administrator or root accounts)." },
        { term: "PAM", definition: "Pluggable Authentication Modules", explanation: "A framework used in Linux that allows a system administrator to 'plug in' different authentication methods." },
        { term: "PAP", definition: "Password Authentication Protocol", explanation: "An insecure authentication protocol that sends the username and password in clear text. Do not use." },
        { term: "PAT", definition: "Port Address Translation", explanation: "The most common form of NAT. It's what allows many devices to share one IP by tracking connections using port numbers." },
        { term: "PBKDF2", definition: "Password-based Key Derivation Function 2", explanation: "A 'key stretching' algorithm. It takes a simple password and runs it through many rounds of hashing to make it stronger and harder to crack." },
        { term: "PBX", definition: "Private Branch Exchange", explanation: "A private telephone network used within a company. Modern ones are digital (VoIP) and run on the network." },
        { term: "PCAP", definition: "Packet Capture", explanation: "A file containing raw network traffic captured by a packet sniffer like Wireshark or tcpdump. (Often has a .pcap extension)." },
        { term: "PCI DSS", definition: "Payment Card Industry Data Security Standard", explanation: "The security standard that all organizations must follow if they handle, process, or store credit card information." },
        { term: "PDU", definition: "Power Distribution Unit", explanation: "A 'smart' power strip used in data center racks to manage and monitor electricity for all the mounted servers." },
        { term: "PEAP", definition: "Protected Extensible Authentication Protocol", explanation: "A common type of EAP. It secures the authentication process by wrapping it inside an encrypted TLS tunnel." },
        { term: "PED", definition: "Personal Electronic Device", explanation: "A general term for any portable electronic device, like a smartphone or tablet." },
        { term: "PEM", definition: "Privacy Enhanced Mail", explanation: "A common file format for digital certificates. It's a Base64-encoded text file, often starting with '-----BEGIN CERTIFICATE-----'." },
        { term: "PFS", definition: "Perfect Forward Secrecy", explanation: "An encryption feature (provided by DHE/ECDHE) that ensures if a server's long-term private key is stolen, it cannot be used to decrypt past recorded sessions." },
        { term: "PGP", definition: "Pretty Good Privacy", explanation: "A popular, commercial program (and standard) for encrypting emails and files. GPG is the free version." },
        { term: "PHI", definition: "Personal Health Information", explanation: "Any health data (diagnosis, records) that is tied to a specific individual. Strictly protected by laws like HIPAA." },
        { term: "PII", definition: "Personally Identifiable Information", explanation: "Any data that can be used to identify a specific person (e.g., SSN, name, address, phone number)." },
        { term: "PIV", definition: "Personal Identity Verification", explanation: "A standard for smart cards used by U.S. federal employees for authentication." },
        { term: "PKCS", definition: "Public Key Cryptography Standards", explanation: "A set of standards (like PKCS #12) that define formats for public key certificates, private keys, etc." },
        { term: "PKI", definition: "Public Key Infrastructure", explanation: "The entire system of hardware, software, and CAs used to create, manage, and distribute digital certificates." },
        { term: "POP", definition: "Post Office Protocol", explanation: "A protocol for receiving email. It typically downloads emails from the server and deletes them, so they only exist on one device." },
        { term: "POTS", definition: "Plain Old Telephone Service", explanation: "The traditional analog telephone network. Can be a security risk (e.g., 'war dialing')." },
        { term: "PPP", definition: "Point-to-Point Protocol", explanation: "An older protocol used to create a direct connection between two network nodes (e.g., dial-up)." },
        { term: "PPTP", definition: "Point-to-Point Tunneling Protocol", explanation: "An old, insecure VPN protocol developed by Microsoft. It's fast but broken. Do not use." },
        { term: "PSK", definition: "Pre-shared Key", explanation: "A secret key that is shared between two parties before they start communicating (e.g., the password for your home Wi-Fi)." },
        { term: "PTZ", definition: "Pan-tilt-zoom", explanation: "A feature of surveillance cameras (CCTV) that allows them to be remotely moved and zoomed for a better view." },
        { term: "PUP", definition: "Potentially Unwanted Program", explanation: "Software that isn't malicious, but is often installed without your full knowledge and can be annoying (e.g., toolbars, adware)." },
        { term: "RA", definition: "Recovery Agent", explanation: "A special user account that is authorized to decrypt data encrypted by other users, in case they lose their key." },
        { term: "RA", definition: "Registration Authority", explanation: "A component of PKI. It verifies the identity of a user before the Certificate Authority (CA) will issue them a certificate." },
        { term: "RACE", definition: "Research and Development in Advanced Communications Technologies in Europe", explanation: "An older European research program that developed the RIPEMD hashing algorithm." },
        { term: "RAD", definition: "Rapid Application Development", explanation: "A software development model that focuses on fast prototyping and iterative development, often at the expense of security." },
        { term: "RADIUS", definition: "Remote Authentication Dial-in User Service", explanation: "A standard, centralized authentication (AAA) server. (e.g., used to authenticate users to a network's Wi-Fi or VPN)." },
        { term: "RAID", definition: "Redundant Array of Inexpensive Disks", explanation: "A technology that combines multiple hard drives into one logical unit to provide fault tolerance (redundancy) and/or performance." },
        { term: "RAS", definition: "Remote Access Server", explanation: "A server (like a VPN or dial-up) that is set up to allow users to connect to a private network from a remote location." },
        { term: "RAT", definition: "Remote Access Trojan", explanation: "Malware that gives an attacker full remote control over your computer, disguised as a legitimate program." },
        { term: "RBAC", definition: "Role-based Access Control", explanation: "An access control model where permissions are assigned to roles (e.g., 'Manager', 'Accountant'), and users are then assigned to those roles. Very scalable." },
        { term: "RBAC", definition: "Rule-based Access Control", explanation: "An access control model (like an ACL or firewall) where access is granted or denied based on a set of 'if-then' rules." },
        { term: "RC4", definition: "Rivest Cipher version 4", explanation: "An old, insecure stream cipher. It was used in WEP and older TLS, but is now broken and must not be used." },
        { term: "RDP", definition: "Remote Desktop Protocol", explanation: "A Microsoft protocol that allows you to see and control another Windows computer over a network. (Runs on port 3389)." },
        { term: "RFID", definition: "Radio Frequency Identifier", explanation: "A tag (like in a key card or inventory) that transmits a unique ID using radio waves. Can be 'skimmed' or cloned." },
        { term: "RIPEMD", definition: "RACE Integrity Primitives Evaluation Message Digest", explanation: "A hashing algorithm, similar to MD5 or SHA. Not as common as SHA-256." },
        { term: "ROI", definition: "Return on Investment", explanation: "A business metric used to justify a security purchase. It shows that the money saved by preventing a breach is greater than the cost of the control." },
        { term: "RPO", definition: "Recovery Point Objective", explanation: "A BCP/DRP metric. It's the maximum amount of data (measured in time) that a business is willing to lose. (e.g., 'RPO = 1 hour' means 'we need backups every hour')." },
        { term: "RSA", definition: "Rivest, Shamir, & Adleman", explanation: "The most popular asymmetric (public-key) algorithm. It's used for encryption, digital signatures, and key exchange." },
        { term: "RTBH", definition: "Remotely Triggered Black Hole", explanation: "A technique used by ISPs to stop a DDoS attack by dropping all traffic to the victim's IP address at the 'edge' of the network." },
        { term: "RTO", definition: "Recovery Time Objective", explanation: "A BCP/DRP metric.It's the maximum amount of time a critical system is allowed to be down after a failure." },
        { term: "RTOS", definition: "Real-time Operating System", explanation: "An OS designed to process data with zero delay (e.g., in a car's brakes, an industrial robot, or a pacemaker)." },
        { term: "RTP", definition: "Real-time Transport Protocol", explanation: "A protocol used to stream audio and video over a network (e.g., in VoIP or video conferencing)." },
        { term: "S/MIME", definition: "Secure/Multipurpose Internet Mail Extensions", explanation: "A standard for encrypting and digitally signing emails. It's built into many email clients (like Outlook)." },
        { term: "SaaS", definition: "Software as a Service", explanation: "A cloud model where the provider manages everything. You just log in and use the app (e.g., Gmail, Office 365)." },
        { term: "SAE", definition: "Simultaneous Authentication of Equals", explanation: "The modern authentication method used in WPA3. It replaces PSK and is much more secure against offline cracking." },
        { term: "SAML", definition: "Security Assertions Markup Language", explanation: "An open standard for authentication and authorization (SSO). It's what lets you log in once and access multiple different web apps." },
        { term: "SAN", definition: "Storage Area Network", explanation: "A high-speed, dedicated network that connects servers directly to storage devices (like a block of hard drives)." },
        { term: "SAN", definition: "Subject Alternative Name", explanation: "A field in a digital certificate that allows multiple different domain names (e.g., `google.com`, `www.google.com`, `mail.google.com`) to be secured with a single certificate." },
        { term: "SASE", definition: "Secure Access Service Edge", explanation: "A modern cloud security model that bundles networking (like SD-WAN) and security (like CASB, WAF) into a single cloud-native service." },
        { term: "SCADA", definition: "Supervisory Control and Data Acquisition", explanation: "A type of ICS (Industrial Control System) used to monitor and control large-scale remote facilities (e.g., a power grid, an oil pipeline)." },
        { term: "SCAP", definition: "Security Content Automation Protocol", explanation: "A NIST standard that uses a set of other standards (like CVE, CVSS, OVAL) to automate vulnerability scanning and compliance." },
        { term: "SCEP", definition: "Simple Certificate Enrollment Protocol", explanation: "A protocol used to automate the process of requesting and enrolling for digital certificates on a large scale." },
        { term: "SD-WAN", definition: "Software-defined Wide Area Network", explanation: "A modern way to manage a WAN (Wide Area Network) using software, making it more flexible and cheaper than traditional MPLS." },
        { term: "SDK", definition: "Software Development Kit", explanation: "A set of tools, libraries, and code samples provided by a vendor to help developers build applications for their platform." },
        { term: "SDLC", definition: "Software Development Lifecycle", explanation: "The formal process for building software: 1. Planning, 2. Analysis, 3. Design, 4. Implementation, 5. Testing, 6. Deployment, 7. Maintenance." },
        { term: "SDLM", definition: "Software Development Lifecycle Methodology", explanation: "A specific model for the SDLC, such as 'Waterfall' (linear) or 'Agile' (iterative and fast)." },
        { term: "SDN", definition: "Software-defined Networking", explanation: "A network architecture where the control plane (the 'brains') is separated from the data plane (the 'muscle'), making the network more programmable." },
        { term: "SE Linux", definition: "Security-enhanced Linux", explanation: "A version of Linux that implements a very strict Mandatory Access Control (MAC) model, significantly improving its security." },
        { term: "SED", definition: "Self-encrypting Drives", explanation: "A hard drive (HDD or SSD) that automatically encrypts all data written to it using a built-in chip. The encryption is 'always on'." },
        { term: "SEH", definition: "Structured Exception Handler", explanation: "A system in Windows for handling errors. 'SEH Overwrite' is a type of exploit that targets this system." },
        { term: "SFTP", definition: "Secured File Transfer Protocol", explanation: "File transfer over SSH. It's a completely different protocol from FTP/FTPS and is a very secure way to transfer files." },
        { term: "SHA", definition: "Secure Hashing Algorithm", explanation: "A family of cryptographic hash functions (e.g., SHA-1, SHA-256). SHA-256 is the current, secure standard." },
        { term: "SHTTP", definition: "Secure Hypertext Transfer Protocol", explanation: "An obsolete and unused alternative to HTTPS. For the exam, HTTPS is the correct answer, not SHTTP." },
        { term: "SIEM", definition: "Security Information and Event Management", explanation: "A tool that collects, aggregates, and correlates logs from all your devices (servers, firewalls) to spot threats and create alerts." },
        { term: "SIM", definition: "Subscriber Identity Module", explanation: "The small card in your phone that identifies you to the mobile network. 'SIM cloning' is an attack." },
        { term: "SLA", definition: "Service-level Agreement", explanation: "A formal contract with a provider (like an ISP or CSP) that defines specific guarantees, such as 99.9% uptime." },
        { term: "SLE", definition: "Single Loss Expectancy", explanation: "A risk calculation formula: SLE = Asset Value ($)  Exposure Factor (%). It's the total amount of money you'd lose if a single threat occurred once." },
        { term: "SMB", definition: "Server Message Block", explanation: "The protocol used by Windows for file sharing, printer sharing, etc., on a local network. (Runs on port 445)." },
        { term: "SMS", definition: "Short Message Service", explanation: "The standard for sending plain-text messages (texts) on mobile phones. Also used as a (less secure) 2FA factor." },
        { term: "SMTP", definition: "Simple Mail Transfer Protocol", explanation: "The standard protocol for sending email from a client to a server, and from server to server. (Runs on port 25)." },
        { term: "SMTPS", definition: "Simple Mail Transfer Protocol Secure", explanation: "An older, secure version of SMTP that uses SSL/TLS. Modern clients just use 'STARTTLS' on the standard ports." },
        { term: "SNMP", definition: "Simple Network Management Protocol", explanation: "A protocol used to monitor and manage network devices (routers, switches). SNMPv3 is the only secure version." },
        { term: "SOAP", definition: "Simple Object Access Protocol", explanation: "An older, XML-based protocol for exchanging structured data, often used for web services (APIs)." },
        { term: "SOAR", definition: "Security Orchestration, Automation, Response", explanation: "A tool that builds on a SIEM. It automates the response to security alerts (e.g., automatically blocking an IP)." },
        { term: "SoC", definition: "System on Chip", explanation: "A single chip that integrates all the main components of a computer (CPU, GPU, RAM), common in IoT and mobile devices." },
        { term: "SOC", definition: "Security Operations Center", explanation: "The team (and building) of security analysts who monitor an organization's security 24/7, using tools like a SIEM." },
        { term: "SOW", definition: "Statement of Work", explanation: "A detailed legal document that defines the specific tasks, deliverables, and timelines for a project (e.g., a pentest)." },
        { term: "SPF", definition: "Sender Policy Framework", explanation: "An email security standard. It's a DNS record that lists which mail servers are allowed to send email for your domain." },
        { term: "SPIM", definition: "Spam over Internet Messaging", explanation: "Unsolicited, 'spam' messages sent over instant messaging (IM) instead of email." },
        { term: "SQL", definition: "Structured Query Language", explanation: "The programming language used to manage and query data in a relational database." },
        { term: "SQLi", definition: "SQL Injection", explanation: "A major web vulnerability where an attacker 'injects' their own SQL commands into a web form to steal or destroy data." },
        { term: "SRTP", definition: "Secure Real-Time Protocol", explanation: "The secure, encrypted version of RTP. Used to provide confidentiality for VoIP and video conferencing." },
        { term: "SSD", definition: "Solid State Drive", explanation: "A modern storage device that uses flash memory (no moving parts). Faster and more reliable than an HDD." },
        { term: "SSH", definition: "Secure Shell", explanation: "The standard, encrypted protocol for remote command-line access to a server (usually Linux). (Runs on port 22)." },
        { term: "SSL", definition: "Secure Sockets Layer", explanation: "The old protocol for encrypting web traffic. It's now broken and has been fully replaced by TLS. People still say SSL, but they mean TLS." },
        { term: "SSO", definition: "Single Sign-on", explanation: "An authentication service (often using SAML or OAuth) that allows you to log in one time and gain access to multiple different applications." },
        { term: "STIX", definition: "Structured Threat Information eXchange", explanation: "A standardized language for sharing threat intelligence (IoCs, TTPs) between systems, often used with TAXII." },
        { term: "SWG", definition: "Secure Web Gateway", explanation: "A solution (like a proxy) that filters all web traffic to block malicious sites, malware, and enforce corporate policies." },
        { term: "TACACS+", definition: "Terminal Access Controller Access Control System", explanation: "A Cisco-proprietary AAA protocol. It's seen as more flexible than RADIUS because it separates Authentication, Authorization, and Accounting." },
        { term: "TAXII", definition: "Trusted Automated eXchange of Indicator Information", explanation: "A protocol for transporting STIX-formatted threat intelligence between different systems." },
        { term: "TCP/IP", definition: "Transmission Control Protocol/Internet Protocol", explanation: "The fundamental protocol suite of the internet. TCP provides reliable, connection-oriented delivery of packets." },
        { term: "TGT", definition: "Ticket Granting Ticket", explanation: "In Kerberos, this is the first ticket a user gets from the KDC. It proves they are authenticated and can be used to request service tickets." },
        { term: "TKIP", definition: "Temporal Key Integrity Protocol", explanation: "The old, insecure encryption protocol used with WPA. It was a 'patch' for WEP and is now replaced by CCMP (WPA2)." },
        { term: "TLS", definition: "Transport Layer Security", explanation: "The modern encryption protocol used to secure web traffic (HTTPS). It replaced SSL." },
        { term: "TOC", definition: "Time-of-check", explanation: "Part of a 'race condition' attack (TOCTOU - Time-of-check to Time-of-use), where an attacker changes a file after it's been checked but before it's been used." },
        { term: "TOTP", definition: "Time-based One-time Password", explanation: "The most common 2FA/MFA algorithm. It generates a new password (like in Google Authenticator) that is valid for a short time (e.g., 30 seconds)." },
        { term: "TOU", definition: "Time-of-use", explanation: "A 'race condition' attack (TOCTOU - Time-of-check to Time-of-use), where an attacker changes a file after it's been checked but before it's been used." },
        { term: "TPM", definition: "Trusted Platform Module", explanation: "A dedicated security chip on a computer's motherboard that securely stores cryptographic keys (e.g., for BitLocker encryption)." },
        { term: "TTP", definition: "Tactics, Techniques, and Procedures", explanation: "A way to profile an attacker. It describes their behaviors (Tactics), their methods (Techniques), and their steps (Procedures)." },
        { term: "TSIG", definition: "Transaction Signature", explanation: "A mechanism for securely authenticating DNS updates, preventing unauthorized changes to DNS records." },
        { term: "UAT", definition: "User Acceptance Testing", explanation: "The final phase of software testing, where real users test the software to see if it meets their needs and works correctly." },
        { term: "UAV", definition: "Unmanned Aerial Vehicle", explanation: "A drone. Can be used for physical surveillance or corporate espionage." },
        { term: "UBA", definition: "User Behavior Analytics", explanation: "A security tool that baselines 'normal' user activity and then flags anomalies (e.g., 'Why is Ruth logging in from China at 3 AM?')." },
        { term: "UDP", definition: "User Datagram Protocol", explanation: "A 'connectionless' protocol (part of TCP/IP). It's fast but unreliable (packets can be lost). Used for streaming, DNS, and VoIP." },
        { term: "UEFI", definition: "Unified Extensible Firmware Interface", explanation: "The modern firmware that has replaced BIOS. It's more secure and supports features like 'Secure Boot'." },
        { term: "UEM", definition: "Unified Endpoint Management", explanation: "The evolution of MDM. It's a single platform to manage all endpoints: mobile phones, tablets, laptops, desktops, and IoT." },
        { term: "UPS", definition: "Uninterruptible Power Supply", explanation: "A battery backup. It provides short-term power to a device (like a server) so it can shut down gracefully during a blackout." },
        { term: "URI", definition: "Uniform Resource Identifier", explanation: "A string of characters that identifies a resource. A URL is the most common type of URI." },
        { term: "URL", definition: "Universal Resource Locator", explanation: "The 'address' of a resource on the internet (e.g., `https://www.google.com`)." },
        { term: "USB", definition: "Universal Serial Bus", explanation: "The standard port for connecting peripherals. Can be a security risk (data theft, malicious devices like a 'Rubber Ducky')." },
        { term: "USB OTG", definition: "USB On the Go", explanation: "A standard that allows mobile devices (like a phone) to act as a host for other USB devices (like a flash drive)." },
        { term: "UTM", definition: "Unified Threat Management", explanation: "An 'all-in-one' security appliance. It's a single box that acts as a firewall, NIPS, WAF, and malware scanner." },
        { term: "UTP", definition: "Unshielded Twisted Pair", explanation: "The most common type of Ethernet cable (like Cat5e, Cat6). It's 'unshielded,' making it vulnerable to EMI (interference)." },
        { term: "VBA", definition: "Visual Basic", explanation: "A scripting language used in Microsoft Office. 'Macro viruses' are written in VBA and are a common malware vector." },
        { term: "VDE", definition: "Virtual Desktop Environment", explanation: "A setup where a user's desktop (OS, apps, data) is run from a virtual machine on a central server. See VDI." },
        { term: "VDI", definition: "Virtual Desktop Infrastructure", explanation: "The technology used to host and manage a VDE (Virtual Desktop Environment). Allows users to access their desktop from anywhere." },
        { term: "VLAN", definition: "Virtual Local Area Network", explanation: "A way to logically divide a single physical network switch into multiple, separate networks for security and traffic management." },
        { term: "VLSM", definition: "Variable Length Subnet Masking", explanation: "A technique for dividing a network into multiple subnets of different sizes to avoid wasting IP addresses." },
        { term: "VM", definition: "Virtual Machine", explanation: "A complete, emulated computer system that runs inside another, physical computer. 'VM escape' is an attack." },
        { term: "VoIP", definition: "Voice over IP", explanation: "A technology that allows you to make phone calls over the internet (an IP network) instead of traditional phone lines." },
        { term: "VPC", definition: "Virtual Private Cloud", explanation: "A private, isolated section of a public cloud (like AWS) where you can launch resources in a virtual network that you control." },
        { term: "VPN", definition: "Virtual Private Network", explanation: "An encrypted 'tunnel' that allows you to securely access a private network over a public network (the internet)." },
        { term: "VTC", definition: "Video Teleconferencing", explanation: "A system for conducting video meetings (e.g., Zoom, Microsoft Teams)." },
        { term: "WAF", definition: "Web Application Firewall", explanation: "A firewall that operates at Layer 7 (Application). It's specifically designed to inspect HTTP traffic and block web attacks like SQLi and XSS." },
        { term: "WAP", definition: "Wireless Access Point", explanation: "Another name for an Access Point (AP). The hardware that broadcasts a Wi-Fi signal." },
        { term: "WEP", definition: "Wired Equivalent Privacy", explanation: "The original, insecure Wi-Fi encryption standard. It's completely broken and must never be used. (Uses RC4)." },
        { term: "WIDS", definition: "Wireless Intrusion Detection System", explanation: "An IDS that specifically monitors the radio frequencies for wireless attacks (e.g., rogue APs, evil twins)." },
        { term: "WIPS", definition: "Wireless Intrusion Prevention System", explanation: "A WIDS that can also block wireless attacks, for example, by sending de-authentication packets to a rogue AP." },
        { term: "WO", definition: "Work Order", explanation: "A formal document authorizing a specific maintenance task or job." },
        { term: "WPA", definition: "Wi-Fi Protected Access", explanation: "The first replacement for WEP. It was a temporary fix that used TKIP. It's also insecure and has been replaced by WPA2." },
        { term: "WPS", definition: "Wi-Fi Protected Setup", explanation: "A feature on routers that lets you connect a device by pressing a button instead of typing a password. It's very insecure and should be disabled." },
        { term: "WTLS", definition: "Wireless TLS", explanation: "An old, deprecated protocol for providing encryption on WAP (Wireless Application Protocol) mobile devices." },
        { term: "XDR", definition: "Extended Detection and Response", explanation: "The evolution of EDR. It collects and correlates threat data from all sources (endpoints, cloud, email, network), not just endpoints." },
        { term: "XML", definition: "Extensible Markup Language", explanation: "A language for structuring data, similar to HTML. It's human-readable and often used for configuration files and APIs (like SOAP)." },
        { term: "XOR", definition: "Exclusive Or", explanation: "A simple, fast logical operation used in encryption. A key part of many ciphers and hashing algorithms." },
        { term: "XSRF", definition: "Cross-site Request Forgery", explanation: "Another name for CSRF. An attack that tricks a user's browser into sending an unauthorized command." },
        { term: "XSS", definition: "Cross-site Scripting", explanation: "A web vulnerability where an attacker injects malicious client-side scripts (like JavaScript) into a trusted website for other users to run." }
    ];
    // --- END OF ABBREVIATIONS ---

    let currentCardIndex = 0;
    let isFlipped = false;

    // Get elements from the DOM
    const flashcard = document.getElementById('flashcard');
    const cardFront = document.getElementById('card-front');
    const cardBack = document.getElementById('card-back');
    const termList = document.getElementById('term-list');
    
    const prevBtn = document.getElementById('prev-btn');
    const flipBtn = document.getElementById('flip-btn');
    const nextBtn = document.getElementById('next-btn');

    // --- NEW: Sort terms alphabetically ---
    terms.sort((a, b) => a.term.localeCompare(b.term));

    // --- NEW: Function to populate the sidebar list ---
    function populateTermList() {
        termList.innerHTML = ''; // Clear any existing items
        terms.forEach((term, index) => {
            const li = document.createElement('li');
            li.textContent = term.term;
            li.dataset.index = index; // Store the index

            // Add click event to jump to the card
            li.addEventListener('click', () => {
                currentCardIndex = index;
                loadCard(currentCardIndex);
            });

            termList.appendChild(li);
        });
    }

    // --- NEW: Function to highlight the active term in the sidebar ---
    function updateActiveTerm(index) {
        // Remove 'active' class from all items
        const allListItems = termList.querySelectorAll('li');
        allListItems.forEach(item => {
            item.classList.remove('active');
        });

        // Add 'active' class to the current item
        const activeItem = termList.querySelector(`li[data-index="${index}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
            // Scroll sidebar to show the active item
            activeItem.scrollIntoView({
                behavior: 'smooth',
                block: 'center'
            });
        }
    }

    // --- UPDATED: Function to load a card ---
    function loadCard(index) {
        if (terms[index]) {
            cardFront.textContent = terms[index].term;
            
            cardBack.innerHTML = `
                <div class="definition">${terms[index].definition}</div>
                <div class="explanation">${terms[index].explanation}</div>
            `;

            // Reset flip state when loading a new card
            if (isFlipped) {
                flashcard.classList.remove('flipped');
                isFlipped = false;
            }

            // Update the sidebar highlight
            updateActiveTerm(index);
        }
    }

    // Function to flip the card
    function flipCard() {
        flashcard.classList.toggle('flipped');
        isFlipped = !isFlipped;
    }

    // Function to show the next card
    function nextCard() {
        currentCardIndex++;
        if (currentCardIndex >= terms.length) {
            currentCardIndex = 0; // Loop back to the start
        }
        loadCard(currentCardIndex);
    }

    // Function to show the previous card
    function prevCard() {
        currentCardIndex--;
        if (currentCardIndex < 0) {
            currentCardIndex = terms.length - 1; // Loop to the end
        }
        loadCard(currentCardIndex);
    }

    // --- Event Listeners ---
    flipBtn.addEventListener('click', flipCard);
    flashcard.addEventListener('click', flipCard); // Allow clicking the card to flip
    nextBtn.addEventListener('click', nextCard);
    prevBtn.addEventListener('click', prevCard);

    // --- NEW: Initial setup ---
    populateTermList(); // Create the sidebar
    loadCard(currentCardIndex); // Load the first card (now '2FA' since it's sorted)
});
