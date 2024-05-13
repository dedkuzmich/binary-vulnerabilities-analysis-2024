from pwn import *


def get_breaks(code):
    lines = code.strip().split("\n")
    addresses = []
    for line in lines:
        addr_str = line.split(":")[1].split(" ")[0]  # Extract 0000000000401EFF
        addresses.append(int(addr_str, 16))  # Convert 0000000000401EFF to 401eff
    addresses = list(dict.fromkeys(addresses))  # Unique entries only
    for addr in addresses:
        addr_hex = hex(addr)
        print(f"br *{addr_hex}")


def main():
    print(hex(0x7f12be8bcd90 - 0x7f12be893000))
    # print(enhex(b"/bin/sh\00"))  # 2f62696e2f736800

    # Create de Bruijn sequence
    seq = cyclic(200).decode()
    print(seq)

    print("\n------------")
    print(cyclic_find(0x61616163))  # rax before cmp eax, 0x539

    print("\n------------")
    print(cyclic_find("maaa"))

    print("\n------------")
    # IDA code:
    code = """
    .text:00000000004012F6                 cmp     eax, 539h
    .text:00000000004012FB                 jz      short loc_401307
    .text:00000000004012FD                 mov     edi, 1          ; status
    .text:0000000000401302                 call    _exit
    .text:0000000000401307 ; ---------------------------------------------------------------------------
    .text:0000000000401307
    .text:0000000000401307 loc_401307:                             ; CODE XREF: main+4D↑j
    .text:0000000000401307                 lea     rax, aAccessGranted ; "ACCESS GRANTED!"
    .text:000000000040130E                 mov     rdi, rax        ; s
    .text:0000000000401311                 call    _puts
    .text:0000000000401316                 mov     eax, 0
    .text:000000000040131B                 leave
    .text:000000000040131C                 retn
    """
    get_breaks(code)


if __name__ == "__main__":
    main()
