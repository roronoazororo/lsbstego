import sys
import re

def to_int(s, base):
    try:
        return int(s, base)
    except ValueError:
        print(f"[!] Error: Could not parse '{s}' in base {base}. Check your inputs.")
        sys.exit(1)

def decode_blob(blob, split_key, base):
    parts = blob.split(split_key)
    if len(parts) != 3:
        print(f"[!] Error: Expected 3 parts after splitting on '{split_key}', got {len(parts)}.")
        print(f"    Make sure you are using the correct split key.")
        sys.exit(1)

    key1 = to_int(parts[0], base)
    key2 = to_int(parts[1], base)
    data_section = parts[2]

    print()
    print("=" * 50)
    print(f"  Split key : {split_key}")
    print(f"  Base      : {base}")
    print(f"  Key1      : {key1}  (from '{parts[0]}' in base {base})")
    print(f"  Key2      : {key2}  (from '{parts[1]}' in base {base})")
    print(f"  Data len  : {len(data_section)} chars ({len(data_section)//2} chunks)")
    print("=" * 50)
    print()

    if len(data_section) % 2 != 0:
        print("[!] Warning: Data section has odd length — last chunk will be dropped.")

    chunks = [data_section[i:i+2] for i in range(0, len(data_section), 2)]

    result = ''
    for chunk in chunks:
        try:
            val = to_int(chunk, base)
            char_code = ((val - key1) ^ key2) - key1
            if 0 < char_code < 65536:
                result += chr(char_code)
            else:
                print(f"[!] Warning: char_code {char_code} out of range for chunk '{chunk}' — skipping.")
        except Exception as e:
            print(f"[!] Warning: Could not decode chunk '{chunk}': {e} — skipping.")

    return result

def main():

    # --- Input: encoded blob ---
    print("[1] Paste the full encoded blob (the value between the quotes in var _a = \"...\").")
    print("    Press Enter twice when done.")
    print()
    lines = []
    while True:
        line = input()
        if line == '' and lines:
            break
        lines.append(line)
    blob = ''.join(lines).strip()

    if not blob:
        print("[!] Error: No blob provided.")
        sys.exit(1)
        
    print()
    print("[2] Enter the split key (e.g. g88, y10, z99, w97):")
    split_key = input("    Split key: ").strip()
    if not split_key:
        print("[!] Error: No split key provided.")
        sys.exit(1)


    print()
    print("[3] Enter the base for parseInt (e.g. 27, 35):")
    try:
        base = int(input("    Base: ").strip())
        if base < 2 or base > 36:
            print("[!] Error: Base must be between 2 and 36.")
            sys.exit(1)
    except ValueError:
        print("[!] Error: Base must be an integer.")
        sys.exit(1)

    print()
    print("[*] Decoding...")
    result = decode_blob(blob, split_key, base)

    if not result:
        print("[!] Decoding produced empty output. Check blob, split key and base.")
        sys.exit(1)

    print()
    print("Code Is")
    print(result)

if __name__ == "__main__":
    main()
