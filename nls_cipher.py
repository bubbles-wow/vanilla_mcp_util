import ctypes

class NlsCipher:
    def __init__(self, seed_bytes: bytes = b"\x98\x84\x5D\x9A\x9E\x8B"):
        """
        Initialize with 6-byte seed.
        Seeds are treated as signed 16-bit integers (Little Endian).
        """
        if len(seed_bytes) < 6:
            raise ValueError("Seed must be at least 6 bytes")
            
        self.s1 = int.from_bytes(seed_bytes[0:2], 'little', signed=True)
        self.s2 = int.from_bytes(seed_bytes[2:4], 'little', signed=True)
        self.s3 = int.from_bytes(seed_bytes[4:6], 'little', signed=True)
        
        # print(f"[DEBUG] Init Seeds: {self.s1}, {self.s2}, {self.s3}")
        self.mask = []
        self.step = []
        self.sbox_blob = []
        self.rsbox_blob = []
        self._generate_keys()

    def _prng_step(self, limit: int) -> int:
        # Wichmann-Hill PRNG
        v5 = ctypes.c_int32(171 * self.s1 - 30269 * int(self.s1 / 177)).value
        self.s1 = v5 if v5 >= 0 else v5 + 30269
        
        v7 = ctypes.c_int32(172 * self.s2 - 30307 * int(self.s2 / 176)).value
        self.s2 = v7 if v7 >= 0 else v7 + 30307
            
        v8 = ctypes.c_int32(170 * self.s3 - 30323 * int(self.s3 / 178)).value
        self.s3 = v8 if v8 >= 0 else v8 + 30323
            
        term1 = self.s1 / 30269.0
        term2 = self.s2 / 30307.0
        term3 = self.s3 / 30323.0
        fraction = (term1 + term2 + term3) - int(term1 + term2 + term3)
        
        return int(fraction * limit)

    def _generate_keys(self) -> None:
        # 6 Rounds
        for _ in range(6):
            # 1. Mask
            self.mask.append(self._prng_step(256) & 0xFF)
            
            # 2. Step
            s = self._prng_step(128)
            self.step.append((s * 2 + 1) & 0xFF)
            
            # 3. S-Box (Fisher-Yates Shuffle)
            p_arr = list(range(256))
            sbox  = [0] * 256
            rsbox = [0] * 256
            
            n = 256
            while n >= 2:
                idx = self._prng_step(n)
                # Swap random element with last element
                val_selected = p_arr[idx]
                val_last = p_arr[n - 1]
                
                p_arr[idx] = val_last
                p_arr[n - 1] = val_selected
                
                # Record in SBox (Value -> Position mapping)
                sbox[val_selected] = n - 1
                rsbox[n - 1] = val_selected
                n -= 1
                
            sbox[p_arr[0]] = 0 # Final element
            rsbox[0] = p_arr[0]
            self.sbox_blob.extend(sbox)
            self.rsbox_blob.extend(rsbox)

    def decrypt(self, data: bytes) -> bytes:
        decrypted = bytearray(len(data))
        curr_mask = list(self.mask)
        curr_step = list(self.step)
        
        for k, byte_val in enumerate(data):
            val = byte_val
            
            # Apply 6 Rounds in Reverse (5 -> 0)
            for r in range(5, -1, -1):
                # Validated Logic: Plain = SBox[Cipher] ^ Mask
                sb_start = r * 256
                
                # Lookup SBox
                val = self.sbox_blob[sb_start + val]
                
                # XOR Mask
                val = val ^ curr_mask[r]
                
            decrypted[k] = val
            
            # Correct Rolling Update of Mask (Mimic C++ behavior)
            # The carry is strictly "If Mask+Step overflows, increment next byte".
            # It does NOT chain if the increment itself overflows.
            for i in range(6):
                sum_val = curr_mask[i] + curr_step[i]
                curr_mask[i] = sum_val & 0xFF
                
                if sum_val >= 256:
                    if i < 5:
                        # Increment next byte, wrap around 255->0, but DO NOT trigger further carry
                        curr_mask[i+1] = (curr_mask[i+1] + 1) & 0xFF

        return decrypted
    
    def encrypt(self, data: bytes) -> bytes:
        encrypted = bytearray(len(data))
        curr_mask = list(self.mask)
        curr_step = list(self.step)
        
        for k, byte_val in enumerate(data):
            val = byte_val
            
            # Apply 6 Rounds in Forward (0 -> 5)
            for r in range(6):
                # Validated Logic: Cipher = RSBox[Plain ^ Mask]
                rsb_start = r * 256
                
                # XOR Mask
                val = val ^ curr_mask[r]
                
                # Lookup RSBox
                val = self.rsbox_blob[rsb_start + val]
                
            encrypted[k] = val
            
            # Mask update logic is identical to decrypt
            for i in range(6):
                sum_val = curr_mask[i] + curr_step[i]
                curr_mask[i] = sum_val & 0xFF
                if sum_val >= 256:
                    if i < 5:
                        curr_mask[i+1] = (curr_mask[i+1] + 1) & 0xFF
        return encrypted