# Headers
**Headers** is a Python-based email header analysis tool designed to help security analysts, threat hunters, and incident responders quickly extract and visualize important information from `.eml` email files. It provides detailed parsing of common headers like `From`, `To`, `Subject`, `Authentication-Results`, and visually neat summaries of `Received` headers — highlighting the path the email took, with the closest hop to the recipient clearly marked.

---

## Features

- Parses and displays key email headers in a clean, colorized terminal output  
- Parses and formats `Authentication-Results` for easier interpretation  
- Extracts and visually highlights the chain of `Received` headers (from oldest to newest)  
- Previews the first 500 characters of the email body  
- Lists any attachments with file names, types, and sizes  


---

## Prerequisites

- Python 3.6+ 

---

## Installation & Usage

```bash
# Clone the repository
git clone https://github.com/BrettmVincent/Headers.git
cd headers
```
```bash
# Run the tool on your .eml file
python3 headers.py /path/to/email_file.eml
```
