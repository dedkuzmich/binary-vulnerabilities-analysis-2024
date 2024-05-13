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
    # Create de Bruijn sequence
    seq = cyclic(5000).decode()
    print(seq)

    print("\n------------")
    print(cyclic_find("aadi"))  # rax before cmp eax, 0x539

    print("\n------------")
    print(cyclic_find("aaqo"))

    print("\n------------")
    # IDA code:
    code = """
    ext:0000000000401EFF                 cmp     eax, 539h
    .text:0000000000401F04                 jz      short loc_401F10
    .text:0000000000401F06                 mov     edi, 1
    .text:0000000000401F0B                 call    sub_4102F0
    .text:0000000000401F10 ; ---------------------------------------------------------------------------
    .text:0000000000401F10
    .text:0000000000401F10 loc_401F10:                             ; CODE XREF: sub_401E41+C3↑j
    .text:0000000000401F10                 lea     rdi, aAccessGranted ; "ACCESS GRANTED!"
    .text:0000000000401F17                 call    sub_411C50
    .text:0000000000401F1C                 mov     eax, 0
    .text:0000000000401F21                 leave
    .text:0000000000401F22                 retn
    """
    get_breaks(code)


if __name__ == "__main__":
    main()
