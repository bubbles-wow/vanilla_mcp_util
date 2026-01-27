import struct
import zlib
import json
import os

MAGIC1, MAGIC2 = 0x267B0B11, 0xBDEB77DE
MAGIC3, MAGIC4, MAGIC5 = 0x02040801, 0x7D7EBBDE, 0x00804021
H1_INIT, H2_INIT, ROT_INIT = 933775118, 2002301995, 0xF4FA8928

def _update_h1_h2(h1: int, h2: int, rot: int, chunk: int) -> tuple[int, int]:
    x1, x2 = (h1 ^ chunk) & 0xFFFFFFFF, (h2 ^ chunk) & 0xFFFFFFFF
    
    # Update h1
    k1 = (((rot ^ MAGIC1) + x2) & 0xFFFFFFFF) & MAGIC2 | MAGIC3
    p1 = x1 * k1
    s1 = ((p1 >> 32) & 0xFFFFFFFF) + (1 if (p1 >> 32) & 0xFFFFFFFF != 0 else 0) + (p1 & 0xFFFFFFFF)
    nh1 = (s1 + (s1 >> 32)) & 0xFFFFFFFF
    
    # Update h2
    k2 = (((rot ^ MAGIC1) + x1) & 0xFFFFFFFF) & MAGIC4 | MAGIC5
    p2 = x2 * k2
    s2 = (p2 & 0xFFFFFFFF) + 2 * ((p2 >> 32) & 0xFFFFFFFF)
    nh2 = (s2 + 2 * (s2 >> 32)) & 0xFFFFFFFF
    
    return nh1, nh2

def _finalize_h1_h2(h1: int, h2: int, rot: int) -> int:
    f2, f1 = (h2 ^ 0x9BE74448) & 0xFFFFFFFF, (h1 ^ 0x9BE74448) & 0xFFFFFFFF
    
    rot_f1 = ((rot << 1) & 0xFFFFFFFF) | (rot >> 31)
    k1 = (rot_f1 ^ MAGIC1) & 0xFFFFFFFF
    
    t1 = ((k1 + f2) & 0xFFFFFFFF) & MAGIC2 | MAGIC3
    p1 = f1 * t1
    s1 = ((p1 >> 32) & 0xFFFFFFFF) + (1 if (p1 >> 32) & 0xFFFFFFFF != 0 else 0) + (p1 & 0xFFFFFFFF)
    y1 = ((s1 & 0xFFFFFFFF) + (s1 >> 32)) ^ 0x66F42C48
    
    t2 = ((k1 + f1) & 0xFFFFFFFF) & MAGIC4 | MAGIC5
    p2 = f2 * t2
    s2 = (p2 & 0xFFFFFFFF) + 2 * ((p2 >> 32) & 0xFFFFFFFF)
    y2 = ((s2 + 2 * (s2 >> 32)) & 0xFFFFFFFF) ^ 0x66F42C48
    
    rot_f2 = ((rot << 2) & 0xFFFFFFFF) | (rot >> 30)
    k2 = (rot_f2 ^ MAGIC1) & 0xFFFFFFFF
    
    t3 = ((k2 + y2) & 0xFFFFFFFF) & MAGIC2 | MAGIC3
    p3 = y1 * t3
    s3 = ((p3 >> 32) & 0xFFFFFFFF) + (1 if (p3 >> 32) & 0xFFFFFFFF != 0 else 0) + (p3 & 0xFFFFFFFF)
    part1 = ((s3 & 0xFFFFFFFF) + (s3 >> 32)) & 0xFFFFFFFF
    
    t4 = ((k2 + y1) & 0xFFFFFFFF) & MAGIC4 | MAGIC5
    p4 = y2 * t4
    p4_64 = p4 & 0xFFFFFFFFFFFFFFFF
    s4 = (p4_64 & 0xFFFFFFFF) + 2 * ((p4_64 >> 32) & 0xFFFFFFFF) + (p4_64 >> 63)
    part2 = ((s4 & 0xFFFFFFFF) + 2 * (s4 >> 32)) & 0xFFFFFFFF
    
    return (part1 ^ part2) & 0xFFFFFFFF

def _hash_directory(data: str | bytes) -> int:
    if isinstance(data, str): data = data.encode('ascii')
    
    last_slash = data.rfind(b'/')
    if last_slash != -1:
        data = data[:last_slash]
    else:
        return 0
    
    if not data:
        return 0

    h1, h2, rot = H1_INIT, H2_INIT, ROT_INIT
    length = len(data)
    i = 0
    while i + 4 <= length:
        rot = ((rot << 1) & 0xFFFFFFFF) | (rot >> 31)
        chunk = struct.unpack('<I', data[i:i+4])[0]
        h1, h2 = _update_h1_h2(h1, h2, rot, chunk)
        i += 4
    if i < length:
        rot = ((rot << 1) & 0xFFFFFFFF) | (rot >> 31)
        chunk = 0
        for j in range(length - i):
            chunk |= data[i + j] << (j * 8)
        h1, h2 = _update_h1_h2(h1, h2, rot, chunk)
    
    return _finalize_h1_h2(h1, h2, rot)

def _hash_file(data: str | bytes) -> int:
    if isinstance(data, str): data = data.encode('ascii')
    h1, h2, rot = H1_INIT, H2_INIT, ROT_INIT
    length = len(data)
    idx = 0
    if idx >= length or data[idx] == 0:
        return _finalize_h1_h2(h1, h2, rot)
    
    while idx < length:
        rot = ((rot << 1) & 0xFFFFFFFF) | (rot >> 31)
        chunk = 0
        for j in range(4):
            if idx < length and data[idx] != 0:
                chunk |= data[idx] << (j * 8)
                idx += 1
            else:
                h1, h2 = _update_h1_h2(h1, h2, rot, chunk)
                return _finalize_h1_h2(h1, h2, rot)
        
        h1, h2 = _update_h1_h2(h1, h2, rot, chunk)
    return _finalize_h1_h2(h1, h2, rot)

def pack_mcpk(input_dir: str, output_file: str) -> None:
    if input_dir is None or input_dir.strip() == "":
        print("[!] Input directory is empty")
        return
    elif not os.path.isdir(input_dir):
        print(f"[!] {input_dir} is not a directory")
        return
    if output_file is None or output_file.strip() == "":
        print("[!] Output file path is empty")
        return

    dir_groups = {}
    all_rel_paths = []
    has_contents_json = False
    is_script_mcp = False
    
    print(f"[+] Scanning files in {input_dir}...")
    for root, _, filenames in os.walk(input_dir):
        for filename in filenames:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, input_dir).replace('\\', '/')
            all_rel_paths.append(rel_path)
            
            d_hash = _hash_directory(rel_path)
            f_hash = _hash_file(filename)
                
            if d_hash == 0 and f_hash == _hash_file("contents.json"):
                has_contents_json = True
            if d_hash == 0 and f_hash == _hash_file("redirect.mcs"):
                is_script_mcp = True
                
            if d_hash not in dir_groups:
                dir_groups[d_hash] = []
            dir_groups[d_hash].append({'f_hash': f_hash, 'full_path': full_path})

    if not is_script_mcp and not has_contents_json:
        print("[+] contents.json not found, auto-generating...")
        contents_list = [{"path": p} for p in all_rel_paths]
        v_data = json.dumps({"content": contents_list}, indent=4).encode('utf-8')
        if 0 not in dir_groups:
            dir_groups[0] = []
        dir_groups[0].append({'f_hash': _hash_file("contents.json"), 'virtual_data': v_data})

    # use signed int32 for sorting
    def signed_int32(n):
        return n if n < 0x80000000 else n - 0x100000000

    sorted_d_hashes = sorted(dir_groups.keys(), key=signed_int32)
    header_size = 57
    dir_table_size = len(sorted_d_hashes) * 12
    index_base_offset = header_size + dir_table_size
    
    num_total_files = sum(len(dir_groups[dh]) for dh in sorted_d_hashes)
    
    print(f"[+] Building {output_file}...")
    with open(output_file, 'wb+') as f_out:
        # prepare header and structures
        header = bytearray(57)
        header[0:4] = b'MCPK'
        header[4:12] = bytes.fromhex("000000009653DA41")
        header[24:34] = b'minecraft\0'
        header[34:48] = bytes.fromhex("0000000000000000000000000000")
        f_out.write(header)
        
        # write directory table
        curr_idx_rel_offset = 0
        for d_hash in sorted_d_hashes:
            f_out.write(struct.pack('<III', d_hash, curr_idx_rel_offset, len(dir_groups[d_hash])))
            curr_idx_rel_offset += len(dir_groups[d_hash]) * 16

        # write index entries
        index_entry_positions = []
        for d_hash in sorted_d_hashes:
            nodes = sorted(dir_groups[d_hash], key=lambda x: signed_int32(x['f_hash']))
            for node in nodes:
                index_entry_positions.append((f_out.tell(), node))
                f_out.write(struct.pack('<IIII', node['f_hash'], 0, 0, 0))
        
        # write compressed data
        data_base_offset = f_out.tell()
        for pos, node in index_entry_positions:
            f_offset = f_out.tell() - data_base_offset
            if 'virtual_data' in node:
                u_data = node['virtual_data']
            else:
                with open(node['full_path'], 'rb') as f_in:
                    u_data = f_in.read()
            
            u_size = len(u_data)
            if not is_script_mcp:
                c_data = zlib.compress(u_data)
            else:
                u_size = 0x7FFFFFFF
                c_data = u_data
            c_size = len(c_data)
                
            f_out.write(c_data)
            node['meta'] = (f_offset, c_size, u_size)
        
        # write index metadata
        for pos, node in index_entry_positions:
            f_out.seek(pos + 4)
            f_out.write(struct.pack('<III', *node['meta']))
        
        # write header updates
        f_out.seek(12)
        f_out.write(struct.pack('<III', header_size, index_base_offset, data_base_offset))
        
        f_out.seek(48)
        f_out.write(struct.pack('<I', dir_table_size))
        
        # write padding
        f_out.seek(0, 2)
        f_out.write(b'\x00' * 129)

    print(f"[+] Successfully packed {num_total_files} files in {len(sorted_d_hashes)} directories.")

def unpack_mcpk(file_path: str, output_dir: str) -> None:
    if file_path is None or file_path.strip() == "":
        print("[!] Input file path is empty")
        return
    elif not os.path.isfile(file_path):
        print(f"[!] File {file_path} does not exist")
        return
    if output_dir is None or output_dir.strip() == "":
        print("[!] Output directory is empty")
        return

    os.makedirs(output_dir, exist_ok=True)
    with open(file_path, 'rb') as f:
        header = f.read(57)
        if header[:4] != b'MCPK':
            print("[!] Not a MCPK file")
            return

        dir_table_offset = struct.unpack('<I', header[12:16])[0]
        index_base_offset = struct.unpack('<I', header[16:20])[0]
        
        f.seek(dir_table_offset)
        dir_count = (index_base_offset - dir_table_offset) // 12
        dir_entries = []
        max_index_rel_offset = 0
        last_dir_files = 0
        for _ in range(dir_count):
            entry = struct.unpack('<III', f.read(12))
            dir_entries.append(entry)
            if entry[1] >= max_index_rel_offset:
                max_index_rel_offset = entry[1]
                last_dir_files = entry[2]
        
        data_base_offset = index_base_offset + max_index_rel_offset + last_dir_files * 16
        print(f"[+] DirTable: {dir_table_offset}, IndexBase: {index_base_offset}, DataBase: {data_base_offset}")
        
        dir_map = {
            de[0]: {
                "offset": de[1],
                "count": de[2],
                "files": {}
            } for de in dir_entries}
        del dir_entries
        for d_hash, info in dir_map.items():
            f.seek(index_base_offset + info["offset"])
            for _ in range(info["count"]):
                fe = struct.unpack('<IIII', f.read(16))
                info["files"][fe[0]] = {
                    "offset": fe[1],
                    "c_size": fe[2],
                    "u_size": fe[3]
                }
        file_list_json = None
        # with open("mcpk_debug_dirmap.json", 'w') as debug_f:
        #     json.dump(dir_map, debug_f, indent=4)

        contents_json_hash = _hash_file("contents.json")
        redirect_mcs_hash = _hash_file("redirect.mcs")
        print(f"[+] Checking for package type...")
        
        is_script_mcp = False
        contents_data = None
        if dir_map[0]["files"].get(contents_json_hash):
            f.seek(data_base_offset + dir_map[0]["files"][contents_json_hash]["offset"])
            c_size = dir_map[0]["files"][contents_json_hash]["c_size"]
            c_data = f.read(c_size)
            try:
                contents_data = zlib.decompress(c_data)
            except:
                contents_data = c_data
            
            with open(os.path.join(output_dir, "contents.json"), 'wb') as out_f:
                out_f.write(contents_data)
            print(f"[+] Extracted contents.json (Directoty Hash: 00000000, File Hash: {contents_json_hash:08X})")
            
            try:
                file_list_json = json.loads(contents_data.decode('utf-8'))
                if isinstance(file_list_json, dict):
                    files_to_extract = file_list_json.get("content", file_list_json)
                else:
                    files_to_extract = file_list_json
                
                if not isinstance(files_to_extract, list):
                    print("[!] contents.json format unexpected")
                    return
            except Exception as e:
                print(f"[!] Failed to parse contents.json: {e}")
                return
        if dir_map[0]["files"].get(redirect_mcs_hash):
            from mcs import decrypt_data
            from anti_confuser import McsMarshal
            
            is_script_mcp = True
            f.seek(data_base_offset + dir_map[0]["files"][redirect_mcs_hash]["offset"])
            c_size = dir_map[0]["files"][redirect_mcs_hash]["c_size"]
            c_data = f.read(c_size)
            
            with open(os.path.join(output_dir, "redirect.mcs"), 'wb') as out_f:
                try:
                    d_data = decrypt_data(c_data)
                    out_f.write(d_data)
                    print(f"[+] Extracted redirect.mcs (Directoty Hash: 00000000, File Hash: {redirect_mcs_hash:08X})")
                    is_script_mcp = True
                except:
                    out_f.write(c_data)
                    print(f"[+] Extracted encrypted redirect.mcs (Directoty Hash: 00000000, File Hash: {redirect_mcs_hash:08X})")
        
        if contents_data is not None:
            del contents_data
            for file_item in files_to_extract:
                file_path_str = file_item.get("path", "")
                norm_path = file_path_str.replace('\\', '/')
                
                d_hash = _hash_directory(norm_path)
                if '/' in norm_path:
                    f_name = norm_path.rsplit('/', 1)[1]
                else:
                    f_name = norm_path
                f_hash = _hash_file(f_name)
                
                if d_hash not in dir_map:
                    print(f"[!] Directory hash not found for {norm_path}, skipping.")
                    continue
                file_info = dir_map[d_hash]["files"].get(f_hash)
                if not file_info:
                    print(f"[!] File hash not found for {norm_path}, skipping.")
                    continue
                
                f.seek(data_base_offset + file_info["offset"])
                c_size = file_info["c_size"]
                u_size = file_info["u_size"]
                c_data = f.read(c_size)
                try:
                    u_data = zlib.decompress(c_data)
                    out_path = os.path.join(output_dir, norm_path)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, 'wb') as out_f:
                        out_f.write(u_data)
                    print(f"[+] Extracted {norm_path} (d_hash={d_hash:08X}, f_hash={f_hash:08X})")
                except Exception as e:
                    print(f"[!] Failed to extract {norm_path}, save origin data (d_hash={d_hash:08X}, f_hash={f_hash:08X}): {e}")
                    out_path = os.path.join(output_dir, norm_path)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, 'wb') as out_f:
                        out_f.write(c_data)
        else:
            for d_hash in dir_map:
                out_dir = os.path.join(output_dir, f"{d_hash:08X}")
                f.seek(index_base_offset + dir_map[d_hash]["offset"])
                for _ in range(dir_map[d_hash]["count"]):
                    fe = struct.unpack('<IIII', f.read(16))
                    f_hash, f_offset, c_size, u_size = fe
                    name = f"{f_hash:08X}"
                    pos = f.tell()
                    f.seek(data_base_offset + f_offset)
                    c_data = f.read(c_size)
                    try:
                        if not is_script_mcp:
                            with open(os.path.join(out_dir, name), 'wb') as out_f:
                                u_data = zlib.decompress(c_data)
                                out_f.write(u_data)
                        else:
                            # decrypt for get filename
                            d_data = decrypt_data(c_data)
                            parser = McsMarshal(d_data)
                            root = parser.r_object()
                            file_name = root.get('filename', b'').decode('utf-8')
                            if file_name == '':
                                os.makedirs(out_dir, exist_ok=True)
                                with open(os.path.join(out_dir, name), 'wb') as out_f:
                                    out_f.write(c_data)
                            else:
                                file_name = file_name.replace('.py', '.mcs')
                                name = file_name
                                target_path = os.path.join(output_dir, file_name)
                                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                # write origin file data
                                with open(target_path, 'wb') as out_f:
                                    out_f.write(c_data)
                        print(f"[+] Extracted {name} (d_hash={d_hash:08X}, f_hash={f_hash:08X})")
                    except Exception as e:
                        print(f"[!] Failed to extract {name}, save origin data (d_hash={d_hash:08X}, f_hash={f_hash:08X}): {e}")
                        os.makedirs(out_dir, exist_ok=True)
                        with open(os.path.join(out_dir, name), 'wb') as out_f:
                            out_f.write(c_data)
                    f.seek(pos)

if __name__ == "__main__":
    print("[*] MCPK Utility")
    print("[*] 1. Unpack MCPK")
    print("[*] 2. Pack Directory to MCPK")
    choice = input("[*] Choice (1/2): ").strip()

    if choice == '1':
        mcpk_path = input("[*] Input MCPK file path: ").strip()
        output_directory = input("[*] Input output directory (Enter to use default): ").strip()
        if output_directory is None or output_directory.strip() == "":
            output_directory = os.path.splitext(os.path.basename(mcpk_path))[0] + "_unpacked"
        unpack_mcpk(mcpk_path, output_directory)
    elif choice == '2':
        input_directory = input("[*] Input directory to pack: ").strip()
        output_mcpk = input("[*] Input output MCPK file path: ").strip()
        if output_mcpk is None or output_mcpk.strip() == "":
            output_mcpk = os.path.basename(os.path.normpath(input_directory))
        if not output_mcpk.endswith(".mcpk"):
            output_mcpk += ".mcpk"
        pack_mcpk(input_directory, output_mcpk)
    else:
        print("[!] Invalid choice")
