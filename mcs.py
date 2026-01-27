import os

from crypto import decrypt_data, encrypt_data

def decrypt_file(filepath, output_path=None):
    if not os.path.exists(filepath):
        print(f"[!] Error: File {filepath} not found.")
        return
    with open(filepath, 'rb') as f:
        origin_content = f.read()
    
    print(f"[+] Processing: {os.path.basename(filepath)}")
    final_content = decrypt_data(origin_content)
    
    # Save
    if output_path is None:
        output_path = filepath + ".pyc"
    
    with open(output_path, 'wb') as f_out:
        f_out.write(final_content)
    print(f"[+] Saved final data to: {output_path}")

def encrypt_file(filepath: str, output_path: str=None, content_type: int=1) -> None:
    if not os.path.exists(filepath):
        print(f"[!] Error: File {filepath} not found.")
        return
    with open(filepath, 'rb') as f:
        origin_content = f.read()
    
    print(f"[+] Processing: {os.path.basename(filepath)}")
    final_content = encrypt_data(origin_content, content_type=content_type)
    
    # Save
    if output_path is None:
        output_path = filepath + ".mcs"
    
    with open(output_path, 'wb') as f_out:
        f_out.write(final_content)
    print(f"[+] Saved final data to: {output_path}")

if __name__ == "__main__":
    mode = input("[*] Select mode: [d]ecrypt or [e]ncrypt? ").strip().lower()
    if mode == 'e':
        target_file = input("[*] Enter path to .pyc file to encrypt: ").strip()
        
        content_type = input("[*] Is this a redirect.mcs file? (y/n): ").strip().lower()
        if content_type == 'y':
            encrypt_file(target_file, content_type=2)
        else:
            encrypt_file(target_file)
    elif mode == 'd':
        target_file = input("[*] Enter path to .mcs file to decrypt: ").strip()
        decrypt_file(target_file)
