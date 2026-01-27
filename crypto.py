import zlib

from nls_cipher import NlsCipher

def encrypt_data(origin_content: bytes, content_type: int = 1) -> bytes:
    if content_type == 2:
        # For redirect.mcs type
        zlib_content = zlib.compress(origin_content, level=9)
        mcpk = b"MCPK"
        header = bytearray(zlib_content[:4])
        for i in range(4):
            header[i] ^= mcpk[i]
        zlib_content = header + zlib_content[4:]
        return zlib_content
    elif content_type == 1:
        wrapped = origin_content[::-1]
        final_content = bytes([b ^ 0x9c for b in wrapped[:130]]) + wrapped[130:]
        zlib_content = zlib.compress(final_content, level=9)
        cipher = NlsCipher()
        encrypted = cipher.encrypt(zlib_content)
        return encrypted
    else:
        return origin_content

def decrypt_data(origin_content: bytes) -> bytes:
    zlib_content = b""
    if origin_content[0] == 0x35:
        # match redirect.mcs
        mcpk = b"MCPK"
        header = bytearray(origin_content[:4])
        for i in range(4):
            header[i] ^= mcpk[i]
        zlib_content = header + origin_content[4:]
    elif origin_content[:2] == b'\xe5\x1f':
        # match encrypted mcs
        cipher = NlsCipher()
        zlib_content = cipher.decrypt(origin_content)
    
    if len(zlib_content) > 2:
        h1, h2 = zlib_content[0], zlib_content[1]
        
        if h1 == 0x78 and h2 in [0x01, 0x9C, 0xDA]:
            try:
                final_content = zlib.decompress(zlib_content)
                
                # Inspect Decompressed Content
                if final_content[:4] == b'bcbc':
                    # Special handling for bcbc files
                    final_content = bytes([b ^ 0x9C for b in final_content[:130]]) + final_content[130:]
                    # Reverse the content
                    final_content = final_content[::-1]
                return final_content
            except zlib.error as e:
                print(f"[!] Zlib Decompression failed: {e}")
                print(f"[!] Data Header: {hex(h1)} {hex(h2)}")
                print(f"[!] Saved raw decrypted data")
                return zlib_content
        else:
            print("[!] Unknown header (Not Zlib). Saving raw decrypted.")
            return zlib_content