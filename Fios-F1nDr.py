#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Device Information Lookup Based on MAC Address

This script processes one or more MAC addresses (either provided directly or
from a file) and attempts to match them against a predefined database of
MAC prefixes to retrieve device-specific information such as model,
manufacturer, UUID format, SSID, and Admin password formats and examples.

Usage:
  Run the script and enter MAC addresses separated by commas,
  or provide a path to a .csv or .txt file containing MAC addresses.

"""

import re
from collections import defaultdict

# MAC_DATA contains information about different device models
# The 'MAC Prefix' field contains space-separated OUI (first three octets) prefixes
MAC_DATA = [
    {
        "Model": "ARC-XCI55AX",
        "Manufacture": "Arcadyan",
        "Device": "Titan2",
        "Serial Prefix": "ABU GRR",
        "Serial Length": 11,
        "MACS": 4,
        "MAC Prefix": "04:09:86 04:70:56 18:58:80 4C:22:F3 54:B7:BD 74:90:BC 84:90:0A 84:A3:29 8C:83:94 A8:A2:37 AC:B6:87 BC:F8:7E C0:D7:AA C8:99:B2 DC:F5:1B F4:CA:E7",
        "UUID": {"template": "bc329e001dd811b28601XXXXXXXXXXXX", "offset": -1},
        "SSID": "Verizon_XXXXXX",
        "SSID Password Length": "15",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <word> is always comprised of a 3-letter, 4-letter, and 5 letter word\n      <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd",
        "SSID Password Ex:": "cedar3-hew-shad",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,M,O,U,W,Y",
        "Admin Password Ex:": "L4VX6BKCD"
    },
    {
        "Model": "ASK-NCM1100",
        "Manufacture": "Arcadyan",
        "Device": "TITAN4",
        "Serial Prefix": "ACL ACN ACQ ACR",
        "Serial Length": 11,
        "MACS": 6,
        "MAC Prefix": "38:88:71",
        "UUID": {"template": "bc329e001dd811b28601XXXXXXXXXXXX", "offset": -2},
        "SSID": "Verizon_XXXXXX",
        "SSID Password Length": "14 or 15",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd",
        "SSID Password Ex:": "woo-quilt6-bow",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,M,O,U,W,Y",
        "Admin Password Ex:": "XCQ9NVGK9"
    },
    {
        "Model": "ASK-NCQ1338E",
        "Manufacture": "Askey",
        "Device": "NCQ1338",
        "Serial Prefix": "AA1 AAM ABB ABF ABG G1C G1D G1E",
        "Serial Length": 11,
        "MACS": 4,
        "MAC Prefix": "2C:EA:DC 4C:AB:F8 74:93:DA 88:DE:7C A4:97:33 FC:12:63",
        "UUID": {"template": "876543219abcdef01234XXXXXXXXXXXX", "offset": -1},
        "SSID": "Verizon_XXXXXX",
        "SSID Password Length": "13 to 15",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd",
        "SSID Password Ex:": "add-paper6-spa",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,O,U",
        "Admin Password Ex:": "CKD3G3MBJ"
    },
    {
        "Model": "CR1000",
        "Manufacture": "Arcadyan",
        "Device": "ath1 or CHR2f",
        "Serial Prefix": "ABJ AB2 AAW AAY ACZ ABP ABQ ABV ABW",
        "Serial Length": 11,
        "MACS": "7 (CR1000A) or 9 (CR1000B)",
        "MAC Prefix": "04:70:56 58:96:71 04:09:86 1C:D6:BE 24:41:FE 34:19:4D 3C:F0:83 4C:22:F3 54:B7:BD 74:90:BC 78:67:0E 84:90:0A 84:A3:29 86:67:0E 88:5A:85 8C:83:94 A8:A2:37 AC:91:9B AC:B6:87 BC:F8:7E C8:99:B2 DC:4B:A1 DC:F5:1B",
        "UUID": {"template": "876543219abcdef01234XXXXXXXXXXXX", "offset": -2},
        "SSID": "FiOS-XXXXX, Fios-XXXXX or Verizon_XXXXXX",
        "SSID Password Length": "13 to 15",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd",
        "SSID Password Ex:": "cost9-nor-jug",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,O,U",
        "Admin Password Ex:": "4TRQJD6GB"
    },
    {
        "Model": "CME1000",
        "Manufacture": "Arcadyan",
        "Device": "CHR2tte",
        "Serial Prefix": "ABA",
        "Serial Length": 11,
        "MACS": 6,
        "MAC Prefix": "4C:22:F3 54:B7:BD 74:90:BC 84:A3:29 8C:83:94 BC:F8:7E DC:F5:1B",
        "UUID": {"template": "bc329e001dd811b28601XXXXXXXXXXXX", "offset": -2},
        "SSID": "Verizon_XXXXXX",
        "SSID Password Length": "15?",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd\n      *There hasn't been many of these collected, so keyspace might be larger",
        "SSID Password Ex:": "oak3-spigot-pay",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,O,U",
        "Admin Password Ex:": "NKFYQD94G"
    },
    { # G3100 or E3200 - Threshold 3 (SSID Length 15, Admin Length 9)
        "Model": "G3100 or E3200",
        "Manufacture": "Arcadyan",
        "Device": "G3100 / E3200",
        "Serial Prefix": "E301 E302 AA62 AA63 AA64",
        "Serial Length": 16,
        "MACS": 6,
        "MAC Prefix": "3C:BD:C5 62:BD:C5 6A:BD:C5 72:BD:C5 74:90:BC DC:F5:1B",
        "UUID": "Appears to be random",
        "SSID": "Verizon_XXXXXX",
        "SSID Password Length": "15",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <word> is always comprised of a 3-letter, 4-letter, and 5 letter word\n      <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd",
        "SSID Password Ex:": "bonny-pug9-trek",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,M,O,U,W,Y",
        "Admin Password Ex:": "HRF4TD9K3",
        "MAC_Ranges": [
            {"start": "3CBDC5500545", "end": "3CBDC5FFFFFF"},
            {"start": "62BDC5500545", "end": "62BDC5FFFFFF"},
            {"start": "6ABDC5500545", "end": "6ABDC5FFFFFF"},
            {"start": "72BDC5500545", "end": "72BDC5FFFFFF"},
            {"start": "7490BC000000", "end": "7490BCFFFFFF"},
            {"start": "DCF51B000000", "end": "DCF51BFFFFFF"}
        ]
    },
    { # G3100 or E3200 - Threshold 2 (SSID Length 15, Admin Length 16)
        "Model": "G3100 or E3200",
        "Manufacture": "Arcadyan",
        "Device": "G3100 / E3200",
        "Serial Prefix": "E301 E302 AA62 AA63 AA64",
        "Serial Length": 16,
        "MACS": 6,
        "MAC Prefix": "62:F8:53 6A:F8:53 72:F8:53 B8:F8:53 3C:BD:C5 62:BD:C5 6A:BD:C5 72:BD:C5",
        "UUID": "Appears to be random",
        "SSID": "Fios-XXXXX",
        "SSID Password Length": "15",
        "SSID Password Format": "<word><number><word><number><word>\nNote: <number> can be 1-4 digits",
        "SSID Password Ex:": "wiry29pat547due",
        "Admin Password Length": "16",
        "Admin Password Format": "All Uppercase, no A,E,I,M,O,U,W,Y",
        "Admin Password Ex:": "canine444telling",
        "MAC_Ranges": [
            {"start": "62F8535BCD40", "end": "62F853FFFFFF"},
            {"start": "6AF8535BCD40", "end": "6AF853FFFFFF"},
            {"start": "72F8535BCD40", "end": "72F853FFFFFF"},
            {"start": "B8F8535BCD40", "end": "B8F853FFFFFF"},
            {"start": "3CBDC5000000", "end": "3CBDC5500544"},
            {"start": "62BDC5000000", "end": "62BDC5500544"},
            {"start": "6ABDC5000000", "end": "6ABDC5500544"},
            {"start": "72BDC5000000", "end": "72BDC5500544"}
        ]
    },
    { # G3100 or E3200 - Threshold 1 (SSID Length 16, Admin Length 16)
        "Model": "G3100 or E3200",
        "Manufacture": "Arcadyan",
        "Device": "G3100 / E3200",
        "Serial Prefix": "E301 E302 AA62 AA63 AA64",
        "Serial Length": 16,
        "MACS": 6,
        "MAC Prefix": "04:A2:22 62:A2:22 6A:A2:22 72:A2:22 62:F8:53 6A:F8:53 72:F8:53 B8:F8:53",
        "UUID": "Appears to be random",
        "SSID": "Fios-XXXXX",
        "SSID Password Length": "16",
        "SSID Password Format": "<word><number><word><number><word>\nNote: <number> can be 1-4 digits",
        "SSID Password Ex:": "sewer85ash98grin",
        "Admin Password Length": "16",
        "Admin Password Format": "All Uppercase, no A,E,I,M,O,U,W,Y",
        "Admin Password Ex:": "allonge455paltry",
        "MAC_Ranges": [
            {"start": "04A222000000", "end": "04A222FFFFFF"},
            {"start": "62A222000000", "end": "62A222FFFFFF"},
            {"start": "6AA222000000", "end": "6AA222FFFFFF"},
            {"start": "72A222000000", "end": "72A222FFFFFF"},
            {"start": "62F853000000", "end": "62F8535BCD39"},
            {"start": "6AF853000000", "end": "6AF8535BCD39"},
            {"start": "72F853000000", "end": "72F8535BCD39"},
            {"start": "B8F853000000", "end": "B8F8535BCD39"}
        ]
    },
    {
        "Model": "FSNO21VA",
        "Manufacture": "Arcadyan",
        "Device": "ath0",
        "Serial Prefix": "ABH",
        "Serial Length": 11,
        "MACS": 1,
        "MAC Prefix": "98:C8:54",
        "UUID": {"template": "876543219abcdef01234XXXXXXXXXXXX", "offset": "last 6 digits of X doesn’t match the MAC address"},
        "SSID": "Verizon_XXXXXX",
        "SSID Password Length": "15",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <word> is always comprised of a 3-letter, 4-letter, and 5 letter word\n            <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd",
        "SSID Password Ex:": "find7-aside-fad",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,O,U",
        "Admin Password Ex:": "4MSKPHWN4"
    },
    {
        "Model": "G1100",
        "Manufacture": "GreenWave",
        "Device": "GreenWave",
        "Serial Prefix": "G1A1 G1A2 S1A1",
        "Serial Length": 15,
        "MACS": 5,
        "MAC Prefix": "18:78:D4 20:C0:47 20:C0:C7 29:6A:0B 48:5D:36 C8:A7:0A D4:A9:28",
        "UUID": "Appears to be random",
        "SSID": "FiOS-XXXXX or Fios-XXXXX",
        "SSID Password Length": "17 or 18",
        "SSID Password Format": "<word><number><word><number><word>\nNote: <number> can be 1-4 digits\n      *It's rare, but some passwords are <number><word><number><word>",
        "SSID Password Ex:": "find7-aside-fad or 279faint5719prized",
        "Admin Password Length": "8 to 10",
        "Admin Password Format": "<word><number><word>",
        "Admin Password Ex:": "toon698sit"
    },
    {
        "Model": "LVSKIHP",
        "Manufacture": "WNC",
        "Device": "Verizon K2",
        "Serial Prefix": "GI1A GI1B",
        "Serial Length": 12,
        "MACS": "Unknown",
        "MAC Prefix": "64:FF:0A 88:5A:85 B8:9F:09 44:E4:EE",
        "UUID": {"template": "876543219abcdef01234XXXXXXXXXXXX", "offset": -2},
        "SSID": "Verizon-5G-Home-XXXX or Verizon-LRV5-XXXX",
        "SSID Password Length": "13 to 15",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd",
        "SSID Password Ex:": "earn-knee6-zap",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,O,U",
        "Admin Password Ex:": "33HJJ7W7Y"
    },
    {
        "Model": "NVG558HX",
        "Manufacture": "Commscope",
        "Device": "<same as Serial Number>",
        "Serial Prefix": "MV2",
        "MACS": 12,
        "MAC Prefix": "20:F3:75 58:60:D8 8C:5A:25 E4:F7:5B",
        "UUID": "Appears to be random",
        "SSID": "Verizon-XXXX",
        "SSID Password Length": "12",
        "SSID Password Format": "12 character, all lowercase\nNote: No 0 or 1 found in 66 SSID passwords",
        "SSID Password Ex:": "45bz6msmw3n3",
        "Admin Password Length": "10",
        "Admin Password Format": "All Digits",
        "Admin Password Ex:": "5497263618"
    },
    {
        "Model": "WCB6200Q",
        "Manufacture": "Broadcom",
        "Device": "<blank>",
        "Serial Prefix": "GWXA GWXB MWXB",
        "Serial Length": 14,
        "MACS": 16,
        "MAC Prefix": "10:78:5B 4C:8B:30 70:F2:20",
        "UUID": "d96c7efc2f8938f1efbd6e5148bfa812",
        "SSID": "FiOS-XXXXX or Fios-XXXXX",
        "SSID Password Length": "17 or 18",
        "SSID Password Format": "<word><number><word><number>\nNote: <number> can be 1-5 digits\n      *It's rare, but some passwords are <number><word><number><word>\n      **This device is an Extender only, it is likely not broadcasting the default SSID/Password",
        "SSID Password Ex:": "ionic03gander4phil",
        "Admin Password Length": "9 or 10",
        "Admin Password Format": "<word><number><word> or <number><word>",
        "Admin Password Ex:": "sources573 or 75immature"
    },
    {
        "Model": "WNC-CR200A",
        "Manufacture": "Arcadyan",
        "Device": "ath0 or ath1",
        "Serial Prefix": "ACA AC0",
        "Serial Length": 11,
        "MACS": 4,
        "MAC Prefix": "58:96:71 24:41:FE AC:91:9B DC:4B:A1",
        "UUID": {"template": "876543219abcdef01234XXXXXXXXXXXX", "offset": -1},
        "SSID": "Verizon_XXXXXX",
        "SSID Password Length": "13 to 15",
        "SSID Password Format": "<word>-<word>-<word> + 1 <digit>\nNote: <digit> can be 3,4,6,7,9 and always after 1st or 2nd word, never 3rd\n      *Rarely the format is <word><number><word><number><word>",
        "SSID Password Ex:": "pod4-grip-hay or drawl7mod8deck",
        "Admin Password Length": "9",
        "Admin Password Format": "All Uppercase, no A,E,I,O,U",
        "Admin Password Ex:": "WVKG3Y9K7"
    }
]

# Set of prefixes that trigger the special G3100/E3200 logic
# This should include all OUIs that are part of the G3100/E3200 configurations
SPECIAL_CASE_G3100_PREFIXES = {
    "04A222", "62A222", "6AA222", "72A222",
    "62F853", "6AF853", "72F853", "B8F853",
    "3CBDC5", "62BDC5", "6ABDC5", "72BDC5",
    "7490BC", "DCF51B"
}


def clean_mac(mac_address):
    """Cleans a MAC address string by removing delimiters and converting to uppercase."""
    # Replace any '.' characters with empty string, then remove other non-hex chars
    return re.sub(r'[^0-9a-fA-F]', '', mac_address.replace('.', '')).upper()

def format_mac(cleaned_mac):
    """Formats a cleaned MAC address into standard AA:BB:CC:DD:EE:FF format."""
    return ':'.join(cleaned_mac[i:i+2] for i in range(0, len(cleaned_mac), 2))

def parse_mac_prefix_string(prefix_string):
    """Parses a space-separated string of MAC prefixes into a set of cleaned prefixes."""
    return {clean_mac(p) for p in prefix_string.split()}

def calculate_uuid(cleaned_mac, uuid_template, uuid_offset):
    """
    Calculates the UUID based on a template, a MAC address, and an offset.
    Assumes 'XXXXXXXXXXXX' is the placeholder for the 12-char (6-byte) MAC segment.
    The offset is applied numerically to the MAC address.
    """
    if not isinstance(uuid_template, str) or 'X' * 12 not in uuid_template:
        return None # Template not in expected format for calculation

    # Handle non-numeric offsets (like the descriptive string for FSNO21VA)
    if not isinstance(uuid_offset, (int, float)):
        return None

    try:
        mac_numeric = int(cleaned_mac, 16)
        adjusted_mac_numeric = mac_numeric + uuid_offset
        
        # Convert adjusted MAC back to 12-character hex, padding with leading zeros
        # Ensure it's exactly 12 hex digits (6 bytes)
        adjusted_mac_hex = f'{adjusted_mac_numeric:012X}'[:12] # Take max 12 chars to prevent overflow issues if offset makes it too long

        # Replace 'X's in the template with the adjusted MAC part
        calculated_uuid_hex = uuid_template.replace('X' * 12, adjusted_mac_hex)
        
        # Format the 32-character hex string into standard UUID format
        # e.g., xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        if len(calculated_uuid_hex) == 32:
            return (f"{calculated_uuid_hex[0:8]}-"
                                    f"{calculated_uuid_hex[8:12]}-"
                                    f"{calculated_uuid_hex[12:16]}-"
                                    f"{calculated_uuid_hex[16:20]}-"
                                    f"{calculated_uuid_hex[20:32]}")
        else:
            return calculated_uuid_hex # Return as is if not 32 chars after replacement

    except ValueError:
        return None # Handle cases where MAC/template conversion fails


def find_device_info(mac_address):
    """
    Finds and returns a list containing a single matching device information dictionary
    for a given MAC address.
    Prioritizes G3100/E3200 models based on specific MAC ranges before general OUI matching.
    """
    cleaned_mac = clean_mac(mac_address)
    if len(cleaned_mac) != 12:
        print(f"Warning: '{mac_address}' is not a valid 12-character MAC address. Skipping.")
        return [], None

    prefix_to_match = cleaned_mac[:6]
    full_mac_numeric = int(cleaned_mac, 16)

    print(f"DEBUG: Processing MAC {cleaned_mac}, Prefix {prefix_to_match}, Numeric {full_mac_numeric}")


    # First, check for specific G3100/E3200 range matches
    for entry in MAC_DATA:
        if entry["Model"] == "G3100 or E3200" and "MAC_Ranges" in entry:
            print(f"DEBUG: Checking G3100/E3200 entry: Model={entry['Model']}, Admin Len={entry.get('Admin Password Length')}, SSID Len={entry.get('SSID Password Length')}")
            for mac_range in entry["MAC_Ranges"]:
                range_start = int(clean_mac(mac_range["start"]), 16)
                range_end = int(clean_mac(mac_range["end"]), 16)
                print(f"DEBUG:   Checking range {hex(range_start)} to {hex(range_end)}")

                if range_start <= full_mac_numeric <= range_end:
                    print(f"DEBUG:   MATCH FOUND in G3100/E3200 range: {entry['Model']} with Admin Len {entry.get('Admin Password Length')}")
                    return [entry], format_mac(prefix_to_match)

    # If no specific G3100/E3200 range match, proceed with general OUI matching
    print("DEBUG: No specific G3100/E3200 range match found. Checking general OUI prefixes.")
    for entry in MAC_DATA:
        model_prefixes = parse_mac_prefix_string(entry["MAC Prefix"])
        if prefix_to_match in model_prefixes:
            print(f"DEBUG: GENERAL OUI MATCH FOUND for {entry['Model']} with prefix {prefix_to_match}")
            return [entry], format_mac(prefix_to_match)
            
    print("DEBUG: No match found after all checks.")
    return [], None


def print_device_info(mac, matches, matched_prefix):
    """Prints the details for all matched devices."""
    print("\n" + "="*50)
    print(f"Searching for MAC: {mac}")
    print(f"Cleaned MAC: {clean_mac(mac)}")

    if not matches:
        print("No matching device information found.")
        print("="*50)
        return

    for i, info in enumerate(matches):
        print(f"\n--- Matched Device {i+1} ---")
        if matched_prefix:
            print(f"Matched Prefix: {matched_prefix}")
        print(f"Model: {info.get('Model', 'N/A')}")
        print(f"Manufacture: {info.get('Manufacture', 'N/A')}")
        print(f"Device: {info.get('Device', 'N/A')}")
        print(f"Serial Prefix: {info.get('Serial Prefix', 'N/A')}")
        print(f"Serial Length: {info.get('Serial Length', 'N/A')}")
        print(f"MACS: {info.get('MACS', 'N/A')}")

        uuid_info = info.get('UUID')
        if isinstance(uuid_info, dict):
            uuid_template = uuid_info.get('template')
            uuid_offset = uuid_info.get('offset')
            
            calculated = calculate_uuid(clean_mac(mac), uuid_template, uuid_offset)
            if calculated:
                print(f"Calculated UUID: {calculated}")
            elif isinstance(uuid_offset, str):
                print(f"UUID Calculation Note: {uuid_offset}")
            else:
                print("Calculated UUID: Could not determine (invalid template/offset or MAC).")
        else:
            print(f"UUID: {uuid_info}")

        print("\n--- Network Information ---")
        print(f"SSID: {info.get('SSID', 'N/A')}")
        print(f"SSID Password Length: {info.get('SSID Password Length', 'N/A')}")
        ssid_password_format = info.get('SSID Password Format', 'N/A')
        if ssid_password_format:
            print("SSID Password Format: " + ssid_password_format)
        else:
            print("SSID Password Format: N/A")
        print(f"SSID Password Ex: {info.get('SSID Password Ex:', 'N/A')}")

        print("\n--- Admin Information ---")
        print(f"Admin Password Length: {info.get('Admin Password Length', 'N/A')}")
        admin_password_format = info.get('Admin Password Format', 'N/A')
        if admin_password_format:
            print("Admin Password Format: " + admin_password_format)
        else:
            print("Admin Password Format: N/A")
        print(f"Admin Password Ex: {info.get('Admin Password Ex:', 'N/A')}")

    print("\n" + "="*50)


def process_mac_addresses(mac_list):
    """Processes a list of MAC addresses and prints their information."""
    for mac in mac_list:
        if not mac.strip():
            continue
        matches, matched_prefix = find_device_info(mac.strip())
        print_device_info(mac.strip(), matches, matched_prefix)

def get_macs_from_file(filepath):
    """Reads MAC addresses from a file, one per line."""
    mac_addresses = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                mac_addresses.extend([m.strip() for m in re.split(r'[,;\s]+', line) if m.strip()])
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
    return mac_addresses

if __name__ == "__main__":
    print("Welcome to the MAC Address Device Information Lookup Script!")
    print("Enter MAC addresses separated by commas, or provide a path to a .csv or .txt file.")
    user_input = input("Enter MACs or file path: ").strip()

    mac_addresses_to_process = []

    if ".csv" in user_input.lower() or ".txt" in user_input.lower():
        mac_addresses_to_process = get_macs_from_file(user_input)
    else:
        mac_addresses_to_process = [m.strip() for m in user_input.split(',') if m.strip()]

    if not mac_addresses_to_process:
        print("No MAC addresses provided or found in the file. Exiting.")
    else:
        process_mac_addresses(mac_addresses_to_process)