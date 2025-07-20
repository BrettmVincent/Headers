import email
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
import sys
import re

# Terminal color codes for nicer output — bolder, stronger “manly” colors
class Colors:
    HEADER = '\033[94;1m'   # Bright Blue
    BLUE = '\033[96;1m'     # Bold Cyan
    CYAN = '\033[97m'       # Bright White
    GREEN = '\033[92;1m'    # Bright Green
    YELLOW = '\033[93;1m'   # Bright Yellow
    RED = '\033[91;1m'      # Bright Red
    BOLD = '\033[1m'
    ENDC = '\033[0m'

def print_banner():
    banner = r"""
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
    """
    print(f"{Colors.HEADER}{banner}{Colors.ENDC}")
    print(f"{Colors.CYAN}{Colors.BOLD}            Email Analysis Tool - by Brett Vincent{Colors.ENDC}\n")

def print_key_value(key, value, indent=2):
    indent_space = ' ' * indent
    print(f"{indent_space}{Colors.BOLD}{key}:{Colors.ENDC} {value}")

def parse_authentication_results(header_value):
    parts = [part.strip() for part in header_value.split(';') if part.strip()]
    parsed = []
    for part in parts:
        if '=' in part:
            method, rest = part.split('=', 1)
            tokens = rest.split()
            result = tokens[0] if tokens else ""
            params = ' '.join(tokens[1:]) if len(tokens) > 1 else ''
            parsed.append((method.strip(), result.strip(), params.strip()))
        else:
            parsed.append((part, '', ''))
    return parsed

def print_authentication_results(header_value):
    print(f"  {Colors.BOLD}Authentication Results:{Colors.ENDC}")
    parsed_results = parse_authentication_results(header_value)
    for method, result, params in parsed_results:
        res_lower = result.lower()
        if res_lower == 'pass':
            color = Colors.GREEN
        elif res_lower == 'fail':
            color = Colors.RED
        elif res_lower == 'neutral':
            color = Colors.YELLOW
        else:
            color = Colors.CYAN
        line = f"    {Colors.CYAN}{method}{Colors.ENDC} = {color}{result}{Colors.ENDC}"
        if params:
            line += f" ({params})"
        print(line)

def parse_received_header(received_header):
    parts = {
        'from': None,
        'by': None,
        'with': None,
        'id': None,
        'for': None,
        'date': None
    }
    header = ' '.join(received_header.splitlines()).strip()
    regex_patterns = {
        'from': r'from\s+(.+?)\s+(?=(by|with|id|for|;|$))',
        'by': r'by\s+(.+?)\s+(?=(from|with|id|for|;|$))',
        'with': r'with\s+(.+?)\s+(?=(from|by|id|for|;|$))',
        'id': r'id\s+(.+?)\s+(?=(from|by|with|for|;|$))',
        'for': r'for\s+(.+?)\s*(?=;|$)',
        'date': r';\s*(.+)$'
    }
    for key, pattern in regex_patterns.items():
        match = re.search(pattern, header, re.IGNORECASE)
        if match:
            parts[key] = match.group(1).strip()
    return parts

def print_received_headers(received_headers):
    print(f"\n{Colors.BOLD}Received Headers (most recent to oldest):{Colors.ENDC}")
    for idx, header in enumerate(reversed(received_headers), 1):
        parsed = parse_received_header(header)
        # Highlight the first parsed (closest to recipient) in bright green
        label_color = Colors.GREEN if idx == 1 else Colors.YELLOW
        print(f"  [{idx}] {label_color}Received Header Summary:{Colors.ENDC}")
        for key in ['from', 'by', 'with', 'id', 'for', 'date']:
            value = parsed.get(key)
            if value:
                print(f"    {Colors.CYAN}{key.capitalize():6}:{Colors.ENDC} {value}")
        print()

def extract_received_headers(msg):
    return msg.get_all('Received', [])

def analyze_email(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        print(f"{Colors.RED}Failed to read or parse email file: {e}{Colors.ENDC}")
        sys.exit(1)

    print_banner()

    print(f"{Colors.HEADER}{Colors.BOLD}Email Analysis Report{Colors.ENDC}")
    print(f"{Colors.BLUE}File: {file_path}{Colors.ENDC}\n")

    headers_of_interest = [
        "From", "To", "Cc", "Bcc", "Date", "Subject",
        "Message-ID", "Return-Path", "Reply-To", "Sender",
        "Authentication-Results"
    ]

    headers = {}
    for header in headers_of_interest:
        value = msg.get(header)
        if value:
            headers[header] = value

    for k, v in headers.items():
        if k.lower() == 'authentication-results':
            print_authentication_results(v)
        else:
            print_key_value(k, v)

    received_headers = extract_received_headers(msg)
    if received_headers:
        print_received_headers(received_headers)

    print(f"\n{Colors.BOLD}Email Body Preview:{Colors.ENDC}")
    if msg.is_multipart():
        parts = [part for part in msg.walk() if part.get_content_type() == 'text/plain']
        if parts:
            body = parts[0].get_content()
        else:
            body = "(No plain text body found)"
    else:
        body = msg.get_content()

    preview = body[:500].replace('\n', ' ').strip() if body else "(No body found)"
    print(f"  {preview}\n")

    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        content_type = part.get_content_type()
        size = len(part.get_content()) if part.get_content() else 0
        attachments.append((filename, content_type, size))

    if attachments:
        print(f"{Colors.BOLD}Attachments:{Colors.ENDC}")
        for i, (filename, ctype, size) in enumerate(attachments, 1):
            print(f"  [{i}] {filename or '(no filename)'} - {ctype} - {size} bytes")
    else:
        print(f"{Colors.BOLD}Attachments:{Colors.ENDC} None")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <email_file.eml>")
        sys.exit(1)

    analyze_email(sys.argv[1])
