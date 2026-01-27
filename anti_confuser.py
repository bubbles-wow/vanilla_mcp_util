import struct

from typing import Any
from io import TextIOBase

from mcs_marshal import McsMarshal

class FakeFileObject(TextIOBase):
    def __init__(self):
        self.data = bytearray()

    def write(self, b: bytes) -> None:
        self.data.extend(b)

    def getvalue(self) -> bytes:
        return bytes(self.data)

# -----------------------------------------------------------------------------
# Opcode Maps (MCS Variant -> Standard) (not complete)
# -----------------------------------------------------------------------------

OP_MAP_A = {
    0x00: 9,    0x01: 5,    0x02: 23,   0x03: 64,   0x08: 25,   0x09: 72,   0x0A: 21,   
    0x0B: 26,   0x0D: 62,   0x0F: 68,   0x10: 22,   0x11: 87,   0x14: 54,   0x15: 20,   
    0x17: 71,   0x18: 63,   0x1A: 81,   0x1B: 30,   0x1C: 31,   0x1D: 32,   0x1E: 33,   
    0x1F: 25,   0x23: 60,   0x27: 66,   0x28: 88,   0x2B: 4,    0x2E: 80,   0x2F: 73,   
    0x34: 3,    0x35: 82,   0x3E: 1,    0x43: 89,   0x47: 24,   0x48: 65,   0x49: 23,   
    0x4D: 23,   0x4F: 85,   0x50: 2,    0x51: 83,   0x52: 84,   0x53: 1,    0x56: 12,   
    0x6B: 93,   0x6E: 99,   0x79: 110,  0x7B: 113,  0x84: 101,  0x85: 136,  0x87: 101,  
    0x88: 116,  0x89: 106,  0x8C: 124,  0x90: 131,  0x9F: 125,  0xA1: 105,  0xA2: 124,  
    0xA3: 109,  0xA6: 134,  0xAF: 103,  0xC2: 143,  0xC3: 111,  0xC9: 90,   0xD0: 120,  
    0xD1: 121,  0xD4: 95,   0xD5: 112,  0xD6: 135,  0xD8: 94,   0xDA: 114,  0xDE: 100,  
    0xE4: 107,  0xE5: 102,  0xE9: 140,  0xEA: 141,  0xEB: 142,  0xF0: 116,  0xF3: 115,  
    0xF7: 132,  0xFA: 108,  0xFC: 133,  0xFE: 92
}

OP_MAP_B = {
    0x01: 83,   0x02: 23,   0x04: 25,   0x05: 71,   0x08: 66,   0x09: 65,   0x0A: 64,
    0x0B: 62,   0x0C: 9,    0x0E: 23,   0x0F: 23,   0x10: 22,   0x12: 82,   0x14: 20,
    0x15: 68,   0x17: 2,    0x1A: 24,   0x1B: 106,  0x1C: 19,   0x1F: 22,   0x20: 27,
    0x22: 4,    0x23: 131,  0x24: 102,  0x25: 20,   0x26: 89,   0x28: 21,   0x2D: 71,
    0x30: 71,   0x32: 93,   0x33: 3,    0x34: 71,   0x35: 23,   0x37: 140,  0x3C: 131,
    0x3D: 131,  0x3E: 131,  0x3F: 131,  0x43: 90,   0x44: 1,    0x48: 56,   0x49: 110,
    0x4A: 22,   0x4E: 5,    0x51: 83,   0x54: 131,  0x55: 131,  0x56: 131,  0x57: 131,
    0x5E: 101,  0x64: 110,  0x6E: 111,  0x72: 145,  0x74: 131,  0x78: 121,  0x82: 107,
    0x8B: 133,  0x8D: 131,  0x8E: 131,  0x8F: 131,  0x94: 110,  0x95: 90,   0xAC: 84,
    0xAF: 103,  0xBC: 121,  0xCC: 116,  0xCD: 124,  0xD5: 107,  0xD6: 120,  0xDB: 109,
    0xDC: 143,  0xEB: 108,  0xFD: 116,  0xB0: 111,  0xF2: 112
}

OP_MAP_C = {
    0x00: 71,   0x01: 11,   0x02: 23,   0x03: 24,   0x04: 133,  0x05: 133,  0x06: 133,  
    0x07: 133,  0x08: 15,   0x09: 20,   0x0C: 25,   0x0D: 21,   0x0F: 82,   0x10: 22,   
    0x11: 60,   0x12: 73,   0x14: 133,  0x17: 133,  0x1A: 23,   0x1B: 71,   0x1D: 12,   
    0x1F: 25,   0x25: 86,   0x26: 81,   0x27: 3,    0x2C: 106,  0x31: 5,    0x32: 68,   
    0x34: 72,   0x3B: 83,   0x3C: 100,  0x3F: 23,   0x40: 115,  0x45: 19,   0x46: 55,   
    0x47: 133,  0x4E: 24,   0x5C: 72,   0x5D: 124,  0x64: 93,   0x65: 81,   0x66: 125,
    0x72: 90,   0x74: 91,   0x77: 103,  0x7A: 92,   0x82: 107,  0x86: 137,  0x8A: 92,   
    0x8B: 109,  0x8C: 95,   0x90: 96,   0x94: 108,  0x96: 116,  0x98: 126,  0x9E: 124,  
    0xA0: 114,  0xAD: 136,  0xB3: 60,   0xB7: 97,   0xC0: 132,  0xC1: 132,  0xC2: 132,  
    0xC7: 110,  0xCA: 99,   0xCC: 143,  0xCF: 116,  0xD2: 131,  0xD3: 115,  0xE2: 124,  
    0xE8: 101,  0xE9: 115,  0xEA: 60,   0xEB: 121,  0xF0: 102,  0xF7: 132,  0xFA: 110,  
    0xFC: 103
}

VERSION_MAP = {-901139953: OP_MAP_A, -1135027243: OP_MAP_B}

def transform_code(mcs_obj: dict) -> bytes:
    magic = mcs_obj['magic']
    op_map = VERSION_MAP.get(magic, OP_MAP_C)
    mcs_code = bytearray(mcs_obj['code'])
    new_code = bytearray()
    i = 0
    while i < len(mcs_code):
        opcode = mcs_code[i]
        if opcode >= 93:
            if i + 2 < len(mcs_code):
                arg = mcs_code[i+1] | (mcs_code[i+2] << 8)
                step = 3
            else:
                arg = 0
                step = len(mcs_code) - i
        else:
            arg = None
            step = 1

        std_op = op_map.get(opcode, opcode)
        new_code.append(std_op)
        if std_op >= 90:
            a = arg if arg is not None else 0
            new_code.extend([a & 0xFF, (a >> 8) & 0xFF])

        # DEBUG: Print mapping
        obj_name = mcs_obj.get('name')
        if isinstance(obj_name, bytes):
            obj_name = obj_name.decode('utf-8', 'ignore')
        a_val = arg if arg is not None else 0
        print(f"DEBUG: {obj_name} magic {magic} | offset {i:3} | mcs_op 0x{opcode:02x} ({opcode:3}) | arg {a_val:3} -> std_op {std_op:3}")

        i += step
    return bytes(new_code)

def w_long(val: int, f: TextIOBase) -> None:
    f.write(b'l')
    if val == 0:
        f.write(struct.pack('<i', 0))
        return
    sign = 1 if val >= 0 else -1
    v = abs(val)
    digits = []
    while v:
        digits.append(v & 0x7FFF)
        v >>= 15
    f.write(struct.pack('<i', sign * len(digits)))
    for d in digits:
        f.write(struct.pack('<H', d))

def w_object(obj: Any, f: TextIOBase) -> None:
    if obj is None:
        f.write(b'N')
    elif obj is True:
        f.write(b'T')
    elif obj is False:
        f.write(b'F')
    elif obj is Ellipsis:
        f.write(b'.')
    elif isinstance(obj, int):
        if -2147483648 <= obj <= 2147483647:
            f.write(b'i')
            f.write(struct.pack('<i', obj))
        else:
            w_long(obj, f)
    elif isinstance(obj, float):
        s = repr(obj).encode()
        f.write(b'f')
        f.write(struct.pack('B', len(s)))
        f.write(s)
    elif isinstance(obj, bytes):
        f.write(b's')
        f.write(struct.pack('<i', len(obj)))
        f.write(obj)
    elif isinstance(obj, str):
        b = obj.encode('utf-8')
        f.write(b's')
        f.write(struct.pack('<i', len(b)))
        f.write(b)
    elif isinstance(obj, (tuple, list, set, frozenset)):
        if isinstance(obj, tuple):
            f.write(b'(')
        elif isinstance(obj, list):
            f.write(b'[')
        elif isinstance(obj, frozenset):
            f.write(b'>')
        else:
            f.write(b'<')
        f.write(struct.pack('<i', len(obj)))
        for item in obj:
            w_object(item, f)
    elif isinstance(obj, dict) and 'magic' in obj:
        f.write(b'c')
        f.write(struct.pack('<i', obj['argcount']))
        f.write(struct.pack('<i', obj['nlocals']))
        f.write(struct.pack('<i', obj['stacksize']))
        f.write(struct.pack('<i', obj['flags']))
        w_object(transform_code(obj), f)
        w_object(tuple(obj['consts']), f)
        w_object(tuple(obj['names']), f)
        w_object(tuple(obj['varnames']), f)
        w_object(tuple(obj['freevars']), f)
        w_object(tuple(obj['cellvars']), f)
        w_object(obj['filename'], f)
        w_object(obj['name'], f)
        f.write(struct.pack('<i', obj['firstlineno']))
        w_object(obj['lnotab'], f)
    elif isinstance(obj, dict):
        f.write(b'{')
        for k, v in obj.items():
            w_object(k, f)
            w_object(v, f)
        f.write(b'0')
    else:
        f.write(b'N')

def restore_data(data: bytes) -> bytes:
    from crypto import decrypt_data
    
    decrypted_data = decrypt_data(data)
    parser = McsMarshal(decrypted_data)
    root = parser.r_object()
    f = FakeFileObject()
    f.write(b"\x03\xf3\x0d\x0a\x00\x00\x00\x00")
    w_object(root, f)
    return f.getvalue()

def main():
    import sys
    if len(sys.argv) < 2:
        return
    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    out_name = sys.argv[1] + ".pyc"
    f = FakeFileObject()
    restored_data = restore_data(data)
    with open(out_name, 'wb') as out_f:
        out_f.write(restored_data)
    print(f"Restored to {out_name}")

if __name__ == "__main__":
    main()
