#  Phishing Email Analysis: 2025-05-27 Malspam Campaign

---

##  Sample

- **Source**: [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)
- **File**: `2025-05-27-VIP-recovery-malspam-0714-UTC.eml`

---

##  Objective

To analyze a phishing email, extract its attachments, unpack any hidden payloads, and determine the nature of the potential threat.

---


##  Step-by-Step Analysis

### 1.  Unzipping the `.zip` Archive

Downloaded a ZIP file containing the `.eml` phishing email. The archive was password-protected using the commonly used password: `infected_20250527`.

**Command:**

```bash
unzip 2025-05-27-VIP-recovery-malspam-0714-UTC.eml.zip
# Password: infected_20250527
```
**Result:**

Extracted: 2025-05-27-VIP-recovery-malspam-0714-UTC.eml

### 2.  Extracting Email Contents

Used munpack to extract email body and any MIME attachments
```bash
munpack 2025-05-27-VIP-recovery-malspam-0714-UTC.eml
```
Extracted Files:
textfile0, textfile1 → email body and headers
UYUM ELK.İNŞ Fiyat Talebi Hk… 2000 adet 2025007586311133_250527132701.r01 → suspicious RAR archive

### 3. Extracting .r01 Archive
Extracted File:
```bash
UYUM ELK.İNŞ Fiyat Talebi Hk… 2000 adet 2025007586311133_250527132701.exe
```
This is a suspicious Windows .exe file — likely the phishing malware payload.

### 4. Hashing the Executable
Calculated file hashes to verify integrity and prepare for malware analysis

```bash
sha256sum *.exe
md5sum *.exe
```
SHA256: aaf3758488397059e00508a1dfe72df4148efef238b4e86038902f968f220c1
MD5: 782a267e2c39af921f068c1777a40170

### 5. VirusTotal Submission
Submitted the .exe to VirusTotal

 No detections - currently undetected by AV engines

 The executable was password-protected, making AV analysis less effective

### 6.  Static String Analysis
Used the strings command to inspect readable content inside the binary.

```bash
strings *.exe | less
```
Notable Strings:
```bash
This program cannot be run in DOS mode.
.text
`.rsrc
@.reloc
*BSJB
v4.0.30319
#Strings
#GUID
#Blob
Column10
button10
*j((, PAs~, &*j(
```

## Observations:
Compiled as a .NET binary targeting .NET Framework v4.0.30319
Likely contains a GUI element (e.g., button10)
Presence of obfuscated or junk strings
No hardcoded URLs, IPs, or domains visible via strings
