A Python tool for rapid analysis of raw email files (.eml) designed to aid security analysts and incident responders in phishing investigations and forensic email examination.

**Features:**

- Parses and displays common email headers including From, To, Subject, Date, and Authentication-Results.
- Extracts and formats complex Authentication-Results headers into readable tables.
- Parses Received headers, breaking down routing details with timestamps.
- Previews email body content (supports plain text and HTML).
- Extracts URLs from the email body, performs DNS resolution to obtain IP addresses, and defangs both URLs and IPs for safe viewing.
- Lists email attachments with metadata: filename, MIME type, size, and calculates MD5, SHA1, and SHA256 hashes for integrity and malware analysis.
- Easy-to-use CLI interface — just provide the path to the .eml file.

**Installation**
```
git clone https://github.com/BrettmVincent/Headers.git
```
**Usage:**
```bash
python3 headers.py <email_file.eml>
```

https://github.com/user-attachments/assets/52610d63-5b2c-41df-9db0-c649b425b820
