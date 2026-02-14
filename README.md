# vanilla_mcp_util
A utility for researching a game's script files, such as `vanilla.mcp`.

## Features
- Unpack/Pack MCPK files.
- Decrypt `.mcs` files to original `.pyc` files.
- Anti-confusion for decrypted `.mcs` files (partially implemented).

## Requirements
Python 3.8 or higher.

## File description
- `mcpk.py`: Unpack MCPK file to a folder, and restore the origin path structure. Compatible for 2 variants (game script pack and resources pack, the first one is not completed implemented).
- `mcs.py`: Decrypt and post process mcs file that unpack from `.mcp` file. Returns the origin confused `.pyc` used for game's python `marshal.loads()`. Compatible for 3 variants `.mcs` file ()
- `anti_confuser.py <mcs_file>`: Anti-confusion for origin `.mcs` files. Returns deobfuscated `.pyc` file (not completely implemented yet, now is okay for `redirect.mcs` in 3 variants)

## About MCPK
- MCPK is a custom archive format used in a game to package scripts and resources.
- About 2 variants:
    1. Script pack: python project structure but with confusion pyc file, contains a `redirect.mcs` in package root path as script loader(McpImporter).
    2. Resource pack: origin resources pack structure, which contains a `contents.json` to list all path in package.

## About MCS
- MCS is a custom encrypted format for python bytecode files (.pyc).
- About 3 variants:
    1. V1 (1.0-2.1)  
    It has standard python codeobject, and non-encrypted str storage. Only opcode remapped.
    2. V2 (2.2-2.6)  
    It has changed the sort of codeobject fields, and str storage is encrypted with XOR or RC4. With opcode remapped too. It adds a `magic` number in code object to identify the game's build-in scripts and modders' scripts.
    3. V3 (2.7+)  
    Similar to variant 2, but with different RC4 decrypt key, code object, and opcode remap table.

## Disclaimer
- This tool is intended for educational purposes only. Use of this tool may violate software licenses or terms of service. 
- Don't use this tool for malicious purposes. The author is not responsible for any misuse of this tool.