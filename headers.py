from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from pathlib import Path
from email import policy
from email.parser import BytesParser
import re
import sys
import socket
from urllib.parse import urlparse
import hashlib

console = Console()

BRIGHT_TITLE_COLOR = "bright_cyan"

def defang_url(url):
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://")

def defang_ip(ip):
    return ip.replace(".", "[.]")

def print_banner():
    banner = r"""
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
Author: Brett Vincent
    """
    console.print(
        Panel(
            banner,
            title=f"[white]Email Analysis Tool[white]",
            style=f"white",
            box=box.ROUNDED,
            border_style="grey50",
            padding=(1, 2),
            expand=True,
        )
    )
    console.print()

def print_headers(headers):
    lines = []
    for key, value in headers.items():
        lines.append(f"[white]{key}:[/white] {value}")
    panel_content = "\n".join(lines)
    console.print(
        Panel(
            panel_content,
            title=f"[bold {BRIGHT_TITLE_COLOR}]Email Headers[/bold {BRIGHT_TITLE_COLOR}]",
            box=box.ROUNDED,
            border_style="grey50",
            padding=(1, 2),
            expand=True,
        )
    )
    console.print()

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
    parsed_results = parse_authentication_results(header_value)
    table = Table(title=f"[bold {BRIGHT_TITLE_COLOR}]Authentication Results[/bold {BRIGHT_TITLE_COLOR}]", box=box.ROUNDED, border_style="grey50", expand=True, show_lines=True)
    table.add_column("Method", style="white", justify="left")
    table.add_column("Result", style="white", justify="left")
    table.add_column("Details", style="white", justify="left")
    for method, result, params in parsed_results:
        table.add_row(method, result, params)
    console.print(table)
    console.print()

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
    lines = []
    for idx, header in enumerate(reversed(received_headers), 1):
        parsed = parse_received_header(header)
        lines.append(f"[white]Received Header #{idx}[white]")
        for key in ['from', 'by', 'with', 'id', 'for', 'date']:
            value = parsed.get(key)
            if value:
                lines.append(f"[white]{key.capitalize():6}:[/white] {value}")
        lines.append("")
    panel_content = "\n".join(lines)
    console.print(
        Panel(
            panel_content,
            title=f"[bold {BRIGHT_TITLE_COLOR}]Received Headers[/bold {BRIGHT_TITLE_COLOR}]",
            box=box.ROUNDED,
            border_style="grey50",
            padding=(1, 2),
            expand=True,
        )
    )
    console.print()

def extract_received_headers(msg):
    return msg.get_all('Received', [])

def extract_urls(text):
    return re.findall(r'https?://\S+', text)

def get_email_bodies(msg):
    bodies = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ['text/plain', 'text/html']:
                try:
                    bodies.append(part.get_content())
                except:
                    continue
    else:
        bodies.append(msg.get_content())
    return bodies

def print_email_body_and_urls(msg):
    bodies = get_email_bodies(msg)
    all_urls = []
    preview_texts = []
    for body in bodies:
        preview_texts.append(body[:500].replace('\n', ' ').strip())
        urls = extract_urls(body)
        all_urls.extend(urls)

    preview = "\n\n---\n\n".join(preview_texts)
    console.print(
        Panel(
            preview,
            title=f"[bold {BRIGHT_TITLE_COLOR}]Email Body Preview[/bold {BRIGHT_TITLE_COLOR}]",
            title_align="center",
            box=box.ROUNDED,
            border_style="grey50",
            padding=(1, 2),
            expand=True,
        )
    )
    console.print()

    unique_urls = list(set(all_urls))
    if unique_urls:
        table = Table(title=f"[bold {BRIGHT_TITLE_COLOR}]Extracted URLs with IPs[/bold {BRIGHT_TITLE_COLOR}]", box=box.ROUNDED, border_style="grey50", expand=True, show_lines=True)
        table.add_column("URL", style="white", justify="left")
        table.add_column("IP Address", style="white", justify="left")
        for url in unique_urls:
            try:
                parsed = urlparse(url)
                ip = socket.gethostbyname(parsed.hostname) if parsed.hostname else "N/A"
            except Exception:
                ip = "Resolution Failed"
            table.add_row(defang_url(url), defang_ip(ip) if ip != "N/A" else ip)
        console.print(table)
        console.print()
    else:
        console.print(
            Panel(
                f"[bold white]URLs:[/bold white] None found",
                box=box.ROUNDED,
                border_style="grey50",
                padding=(1, 2),
                expand=True,
            )
        )
        console.print()

def print_attachments(attachments):
    if attachments:
        table = Table(title="Attachments", box=box.ROUNDED, border_style="grey50", expand=True, show_lines=True)
        table.add_column("File Name", style="white", justify="left")
        table.add_column("MIME Type", style="white", justify="left")
        table.add_column("Size (bytes)", style="white", justify="left")
        table.add_column("MD5 Hash", style="white", justify="left")
        table.add_column("SHA1 Hash", style="white", justify="left")
        table.add_column("SHA256 Hash", style="white", justify="left")
        for filename, ctype, size, md5, sha1, sha256 in attachments:
            table.add_row(filename or "(no filename)", ctype, str(size), md5, sha1, sha256)
        console.print(table)
        console.print()
    else:
        console.print(
            Panel(
                f"[bold white]Attachments:[/bold white] None",
                box=box.ROUNDED,
                border_style="grey50",
                padding=(1, 2),
                expand=True,
            )
        )
        console.print()

def analyze_email(file_path):
    path = Path(file_path)
    if not path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        sys.exit(1)

    try:
        with open(path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        console.print(f"[red]Failed to read or parse email file: {e}[/red]")
        sys.exit(1)

    print_banner()
    console.print(
        Panel(
            f"[bold white]Analyzing file:[/bold white] {path.name}",
            box=box.ROUNDED,
            border_style="grey50",
            padding=(1, 2),
            expand=True,
        )
    )
    console.print()

    headers_of_interest = [
        "From", "To", "Cc", "Bcc", "Date", "Subject",
        "Message-ID", "Return-Path", "Reply-To", "Sender",
        "Authentication-Results"
    ]

    headers = {}
    auth_results = None
    for header in headers_of_interest:
        value = msg.get(header)
        if value:
            if header.lower() == "authentication-results":
                auth_results = value
            else:
                headers[header] = value

    if headers:
        print_headers(headers)
    if auth_results:
        print_authentication_results(auth_results)

    received_headers = extract_received_headers(msg)
    if received_headers:
        print_received_headers(received_headers)

    print_email_body_and_urls(msg)

    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        content_type = part.get_content_type()
        raw_content = part.get_content()
        size = len(raw_content) if raw_content else 0
        if raw_content:
            md5_hash = hashlib.md5(raw_content).hexdigest()
            sha1_hash = hashlib.sha1(raw_content).hexdigest()
            sha256_hash = hashlib.sha256(raw_content).hexdigest()
        else:
            md5_hash = sha1_hash = sha256_hash = ""
        attachments.append((filename, content_type, size, md5_hash, sha1_hash, sha256_hash))
    print_attachments(attachments)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        console.print(f"[red]Usage: python {sys.argv[0]} <email_file.eml>[/red]")
        sys.exit(1)

    analyze_email(sys.argv[1])
