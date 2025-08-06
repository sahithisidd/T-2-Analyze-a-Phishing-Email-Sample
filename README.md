#  Phishing Analysis: 2025-05-27 Malspam Campaign

##  Task Objective
To analyze a suspicious phishing email by extracting its content, inspecting attachments, identifying potential indicators of compromise (IOCs), and assessing the risk level based on static inspection and public malware intelligence sources.

## Tools Used
* Kali Linux (Operating System)
* unzip — for extracting zipped phishing samples
* munpack — for parsing and extracting MIME-encoded .eml email contents
* unrar — to extract .r01 archive files
* strings — to extract printable strings from executables
* sha256sum, md5sum — to generate file hashes for malware identification
* VirusTotal — for multi-engine antivirus scanning and threat reputation



