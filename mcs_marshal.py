import struct

from typing import Any

_NULL = object()

class StopIterationException(Exception):
    pass

class McsRC4:
    def __init__(self, key: bytes):
        self.key = key
        self.sbox = [0] * 256
        self._ksa()

    def _ksa(self):
        key_len = len(self.key)
        for i in range(256):
            self.sbox[i] = i
        j = 0
        for i in range(256):
            j = (j + self.sbox[i] + self.key[i % key_len]) & 0xFF
            self.sbox[i], self.sbox[j] = self.sbox[j], self.sbox[i]
        self.i = self.j = 0

    def decrypt(self, data: bytes) -> bytes:
        data = bytearray(data)
        for k in range(len(data)):
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.sbox[self.i]) & 0xFF
            self.sbox[self.i], self.sbox[self.j] = self.sbox[self.j], self.sbox[self.i]
            t = (self.sbox[self.i] + self.sbox[self.j]) & 0xFF
            data[k] ^= self.sbox[t]
        return bytes(data)

class McsMarshal:
    RC4_KEY = b"\x8d\x06\xe8\xc8\xb7\xd7\xb7\x28\x46\x51\xae\x04"

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.refs = []

    def r_byte(self) -> int:
        val = self.data[self.pos]
        self.pos += 1
        return val

    def r_short(self) -> int:
        if self.pos + 2 > len(self.data):
            return 0
        v = struct.unpack('<H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        return v

    def r_int(self) -> int:
        if self.pos + 4 > len(self.data):
            val = 0
            for i in range(4):
                if self.pos < len(self.data):
                    val |= self.data[self.pos] << (i * 8)
                    self.pos += 1
                else:
                    val |= 0xFF << (i * 8)
            return struct.unpack('<i', struct.pack('<I', val & 0xFFFFFFFF))[0]
        val = struct.unpack('<i', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return val

    def r_long(self) -> int:
        size = self.r_int()
        if size == 0:
            return 0
        n = abs(size)
        res = 0
        for i in range(n):
            digit = self.r_short()
            res |= (digit & 0x7FFF) << (i * 15)
        return res if size > 0 else -res

    def r_string(self, size: int = None) -> bytes:
        if size is None:
            size = self.r_int()
        if size < 0:
            return b""
        if self.pos + size > len(self.data):
            size = len(self.data) - self.pos
        res = self.data[self.pos:self.pos+size]
        self.pos += size
        return res

    def r_object(self) -> Any:
        tag = self.r_byte()
        
        # simple singletons and constants
        if tag == 48: # '0'
            return _NULL
        if tag in (78, 110): # 'N', 'n'
            return None
        if tag == 84: # 'T'
            return True
        if tag == 70: # 'F'
            return False
        if tag == 46: # '.'
            return Ellipsis
        if tag == 83: # 'S' - StopIteration
            return StopIterationException
        
        # numeric types
        if tag == 105: # 'i'
            return self.r_int()
        if tag == 73: # 'I' - 64-bit int
            v = struct.unpack('<q', self.data[self.pos:self.pos+8])[0]
            self.pos += 8
            return v
        if tag in (108, 76): # 'l', 'L'
            return self.r_long()
        if tag == 102: # 'f'
            sz = self.r_byte()
            return float(self.r_string(sz))
        if tag == 103: # 'g'
            v = struct.unpack('<d', self.data[self.pos:self.pos+8])[0]
            self.pos += 8
            return v
            
        # strings and references
        if tag == 115: # 's'
            return self.r_string()
        if tag == 116: # 't' - Interned
            s = self.r_string()
            self.refs.append(s)
            return s
        if tag == 117: # 'u' - Unicode
            return self.r_string().decode('utf-8', 'ignore')
        if tag == 82: # 'R' - Reference
            idx = self.r_int()
            return self.refs[idx] if idx < len(self.refs) else None
            
        # containers
        if tag == 40: # '(' - Tuple
            n = self.r_int()
            return tuple(self.r_object() for _ in range(n))
        if tag == 91: # '[' - List
            n = self.r_int()
            return [self.r_object() for _ in range(n)]
        if tag in (60, 62): # '<', '>' - Set/FrozenSet
            n = self.r_int()
            items = [self.r_object() for _ in range(n)]
            return frozenset(items) if tag == 62 else set(items)
        if tag == 123: # '{' - Dict
            d = {}
            while True:
                k = self.r_object()
                if k is _NULL:
                    break
                d[k] = self.r_object()
            return d
            
        # encrypted or obfuscated types
        if tag in (109, 49): # 'm', '1' - RC4
            return McsRC4(self.RC4_KEY).decrypt(self.r_string())
        if tag == 98: # 'b' - RC4 with reference
            dec = McsRC4(self.RC4_KEY).decrypt(self.r_string())
            self.refs.append(dec)
            return dec
        if tag in (8, 14, 15): # XOR 0x8D 
            raw = bytearray(self.r_string())
            for i in range(len(raw)):
                raw[i] ^= 0x8D
            res = bytes(raw)
            if tag == 15:
                self.refs.append(res)
            return res

        if tag in (99, 77, 111): # 'c', 'M', 'o'
            return self.r_code_object(tag)
            
        raise ValueError(f"Unknown Tag: {tag} ({chr(tag) if 32 <= tag <= 126 else '?'}) at {self.pos-1}")

    def r_code_object(self, tag: int) -> dict:
        if tag == 99:  # 'c'
            obj = {
                'argcount': self.r_int(),
                'nlocals': self.r_int(),
                'stacksize': self.r_int(),
                'flags': self.r_int(),
                'code': self.r_object(),
                'consts': self.r_object(),
                'names': self.r_object(),
                'varnames': self.r_object(),
                'freevars': self.r_object(),
                'cellvars': self.r_object(),
                'filename': self.r_object(),
                'name': self.r_object(),
                'firstlineno': self.r_int(),
                'lnotab': self.r_object(),
                'magic': None
            }
        elif tag == 77:  # 'M'
            obj = {
                'argcount': self.r_int(),
                'lnotab': self.r_object(),
                'cellvars': self.r_object(),
                'firstlineno': self.r_int(),
                'varnames': self.r_object(),
                'consts': self.r_object(),
                'name': self.r_object(),
                'stacksize': self.r_int(),
                'freevars': self.r_object(),
                'names': self.r_object(),
                'code': self.r_object(),
                'flags': self.r_int(),
                'filename': self.r_object(),
                'nlocals': self.r_int(),
                'magic': self.r_int()
            }
        elif tag == 111:  # 'o'
            obj = {
                'nlocals': self.r_int(),
                'flags': self.r_int(),
                'consts': self.r_object(),
                'stacksize': self.r_int(),
                'varnames': self.r_object(),
                'argcount': self.r_int(),
                'cellvars': self.r_object(),
                'names': self.r_object(),
                'freevars': self.r_object(),
                'name': self.r_object(),
                'code': self.r_object(),
                'firstlineno': self.r_int(),
                'lnotab': self.r_object(),
                'magic': self.r_int(),
                'filename': self.r_object()
            }
        return obj
