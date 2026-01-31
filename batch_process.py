import os
import sys
import subprocess

from concurrent.futures import ThreadPoolExecutor
from anti_confuser import restore_data

def file_handler(input_path: str, output_path: str=None) -> None:
    if not os.path.exists(input_path):
        print(f"[!] Error: File {input_path} not found.")
        return
    with open(input_path, 'rb') as f:
        origin_content = f.read()
    
    print(f"[+] Processing: {os.path.basename(input_path)}")
    final_content = restore_data(origin_content)
    
    # Save
    if output_path is None:
        output_path = input_path + ".pyc"
    
    with open(output_path, 'wb') as f_out:
        f_out.write(final_content)
    subprocess.run(['pycdas', output_path, '-o', output_path + '_asm.txt'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Saved restored data to: {output_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python batch_process.py <input_folder> [output_folder]")
        return
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    pool = ThreadPoolExecutor(max_workers=16)
    if os.path.isdir(input_file):
        for root, dirs, files in os.walk(input_file):
            for filename in files:
                file_path = os.path.join(root, filename)
                relative_path = os.path.relpath(file_path, input_file)
                out_path = None
                if output_file:
                    out_dir = os.path.join(output_file, os.path.dirname(relative_path))
                    os.makedirs(out_dir, exist_ok=True)
                    out_path = os.path.join(out_dir, os.path.basename(relative_path) + ".pyc")
                pool.submit(file_handler, file_path, out_path)
    else:
        pool.submit(file_handler, input_file, output_file)
        
    pool.shutdown(wait=True)
    
if __name__ == "__main__":
    main()