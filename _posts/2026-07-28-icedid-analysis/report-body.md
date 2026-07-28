# Background

IcedID, also known as BokBot, is a Windows malware family. It was originally known as a banking trojan designed to steal online banking credentials and financial information, but in later campaigns it has been used as a loader for delivering additional payloads.

This report analyzes an IcedID sample that was first submitted to VirusTotal in 2019. The analysis covers the unpacking performed by the first stage, runtime API resolution, 64-bit API resolution through Heaven's Gate, inline hooks placed on `NtCreateUserProcess` and `RtlExitUserProcess`, second-stage injection into `svchost.exe`, and C2 communication.

Rather than simply creating a child process and executing the payload, this sample hooks `NtCreateUserProcess` to hijack control during creation of the `svchost.exe` process. It then hooks `RtlExitUserProcess` to execute the second stage during the termination routine of `svchost.exe`. 

# Basic Information

## Sample

File name: `5.exe`  
File type: EXE

| Type | Hash |
| ------ | ---------------------------------------------------------------- |
| MD5 | 6d176c6c7d58d921b773f83b1846750d |
| SHA256 | b8113a604e6c190bbd8b687fd2ba7386d4d98234f5138a71bcf15f0a3c812e91 |

## VirusTotal

| Type | Date and time |
| ---------------- | ----------------------- |
| First submission | 2019-06-06 17:37:46 UTC |
| Last submission | 2026-04-21 02:37:05 UTC |

## Sandbox Execution Result

- [Any.run](https://app.any.run/tasks/6114e7fd-21ae-4769-a04c-672bda2e3185)

# Triage Analysis

DIE identifies the sample as a Win32 EXE.

![file-20260604083138273.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260604083138273.png" | relative_url }})

# Unpacking

The unpacked PE data is written into the region where the original execution image was mapped.

First, shellcode that unpacks the PE data is written to memory whose protection is changed to RWX by `VirtualProtect`, and then executed. This shellcode then unpacks the PE data into RWX memory allocated with `VirtualAlloc`.

![file-20260604085319275.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260604085319275.png" | relative_url }})

The original execution image is overwritten with zeros, and the unpacked PE data is mapped into that region.

![file-20260604085232589.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260604085232589.png" | relative_url }})

Finally, execution is transferred to the entry point of the unpacked PE data through an indirect jump.

![file-20260604090131902.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260604090131902.png" | relative_url }})

# Unpacked Module

DIE identifies the unpacked module as a Win32 EXE.

![file-20260607111005203.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607111005203.png" | relative_url }})

The `.data` section accounts for most of the file and has high entropy. This strongly suggests that encrypted data is stored in this region.

![file-20260604212245968.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260604212245968.png" | relative_url }})

## Checking Command-Line Arguments

The execution path branches depending on whether the command-line argument `"-q="` is provided.

- If `"-q="` is not provided:
    - The sample obtains a TSC (Time Stamp Counter) value using the `rdtsc` instruction, converts it  to an unsigned integer, uses it as the value of the `"-q="` argument, and re-executes the currently running module with `CreateProcessA`.
- If `"-q="` is provided:
    - The sample installs a hook on `NtCreateUserProcess` and then create `svchost.exe` process.

![file-20260607111611146.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607111611146.png" | relative_url }})

## Runtime API Resolution

### 32-bit API Resolution Using API Hashing

The sample resolves APIs from `ntdll.dll` at runtime. It obtains the base address of `ntdll.dll` with `GetModuleHandleA` and resolves API addresses by parsing the module's export directory. The hash of each API name is calculated using a combination of ROR and XOR operations, as shown below. When the calculated hash matches a hardcoded value, the corresponding function address is stored.

![file-20260607113124288.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607113124288.png" | relative_url }})

After resolving an API address, the sample also saves the first 6 bytes from that address. In many cases, these 6 bytes correspond to the beginning of a syscall stub that includes an instruction for loading the system call number with a `mov` instruction. The sample likely saves these bytes for later unhooking or direct invocation.

![file-20260604223213496.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260604223213496.png" | relative_url }})

### 64-bit API Resolution Using Heaven's Gate

If the processor architecture obtained with `GetNativeSystemInfo` is AMD64, the sample also resolves 64-bit APIs.

First, it executes a `retf` instruction with the argument value 33, causing the following bytes to be executed as 64-bit code. In the example below, the bytes after the `nop` are interpreted and executed as 64-bit instructions.

![file-20260607113915022.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607113915022.png" | relative_url }})

When the bytes after `retf` are disassembled as 64-bit code, they appear as follows.

```text
00401E9C: 90                       NOP
00401E9D: 49 8B 44 24 60           MOV        RAX, QWORD PTR [R12 + 0x60]
00401EA2: 90                       NOP
00401EA3: 90                       NOP
00401EA4: 48 8B 40 18              MOV        RAX, QWORD PTR [RAX + 0x18]
00401EA8: 90                       NOP
00401EA9: 90                       NOP
00401EAA: 90                       NOP
00401EAB: 90                       NOP
00401EAC: 48 8B 40 30              MOV        RAX, QWORD PTR [RAX + 0x30]
00401EB0: 90                       NOP
00401EB1: 90                       NOP
00401EB2: 48 8B 40 10              MOV        RAX, QWORD PTR [RAX + 0x10]
00401EB6: 90                       NOP
00401EB7: 90                       NOP
00401EB8: 90                       NOP
00401EB9: 90                       NOP
00401EBA: 90                       NOP
00401EBB: 90                       NOP
00401EBC: 90                       NOP
00401EBD: 48 89 C2                 MOV        RDX, RAX
00401EC0: 90                       NOP
00401EC1: 90                       NOP
00401EC2: 90                       NOP
00401EC3: 90                       NOP
00401EC4: 90                       NOP
00401EC5: 48 C1 EA 20              SHR        RDX, 0x20
00401EC9: 90                       NOP
00401ECA: 90                       NOP
00401ECB: 90                       NOP
```

According to the [Black-Hat-Zig article](https://black-hat-zig.cx330.tw/Advanced-Malware-Techniques/Process-Injection/Heavens-Gate/heavens_gate/#runsimulatedcode), in the 64-bit execution context of WOW64, `R12` points to the 64-bit TEB. This sample appears to rely on that assumption and obtains the 64-bit PEB from `[R12+0x60]`. It then follows `PEB->Ldr->InInitializationOrderModuleList.Flink` and stores the `DllBase` value of the first entry, namely `ntdll.dll`, in `RAX`. It then extracts the upper 32 bits into `RDX`. This is likely done to represent the 64-bit `DllBase` value as `RDX:RAX` in the 32-bit context.

The sample then returns to the 32-bit context by executing `retf` with `0x22` set, as shown below.

![file-20260607115001744.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607115001744.png" | relative_url }})

Next, the sample enters the 64-bit code context again through Heaven's Gate and executes the following code.

```text
00401F32: 90                       NOP
00401F33: 90                       NOP
00401F34: FF 75 F0                 PUSH       QWORD PTR [RBP + 0xFFFFFFFFFFFFFFF0]
00401F37: 90                       NOP
00401F38: 90                       NOP
00401F39: 59                       POP        RCX
00401F3A: FF 75 E8                 PUSH       QWORD PTR [RBP + 0xFFFFFFFFFFFFFFE8]
00401F3D: 90                       NOP
00401F3E: 90                       NOP
00401F3F: 5E                       POP        RSI
00401F40: FF 75 E0                 PUSH       QWORD PTR [RBP + 0xFFFFFFFFFFFFFFE0]
00401F43: 90                       NOP
00401F44: 5F                       POP        RDI
00401F45: 90                       NOP
00401F46: 90                       NOP
00401F47: FC                       CLD
00401F48: F3 A4                    REP MOVSB
00401F4A: 90                       NOP
```

In this code, `RDI` is set to the address of a heap region allocated with `HeapAlloc`, `RSI` is set to the address of the 64-bit `ntdll.dll`, and `RCX` is set to `0x1000`. The `rep movsb` instruction then copies `0x1000` bytes from the beginning of the 64-bit `ntdll.dll` into the heap region. In other words, the header data of `ntdll.dll` is copied into the heap.

The sample then parses the export directory of the copied 64-bit `ntdll.dll` header in the same manner as the 32-bit API resolution routine and resolves 64-bit APIs.

## API Hooking

### Hooking NtCreateUserProcess

This sample installs hooks on two APIs, `NtCreateUserProcess` and `RtlExitUserProcess`, to execute malicious code when `svchost.exe` is started and when the `svchost.exe` process exits.

First, immediately before executing `svchost.exe` through `CreateProcessA`, the sample installs a hook on `NtCreateUserProcess`.

![file-20260607120125748.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607120125748.png" | relative_url }})

When installing the hook, the sample uses `NtProtectVirtualMemory` to grant RWX permissions to the first five bytes of `NtCreateUserProcess`, and then overwrites those five bytes with the following instruction.

```text
JMP <hook function address> - <NtCreateUserProcess address> - 5
```

As a result, when `CreateProcessA` is executed to launch `svchost.exe`, `NtCreateUserProcess` is called internally and execution is immediately transferred to the specified hook function. Finally, the sample restores the memory protection with `NtProtectVirtualMemory`.

![file-20260607120342088.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607120342088.png" | relative_url }})

`NtCreateUserProcess` before the hook is installed:

![file-20260605112711092.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260605112711092.png" | relative_url }})

`NtCreateUserProcess` after the hook is installed:

![file-20260605130138230.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260605130138230.png" | relative_url }})

The hook function for `NtCreateUserProcess` removes the hook, executes the original `NtCreateUserProcess`, injects the second-stage PE data into `svchost.exe`, and installs a hook on `RtlExitUserProcess`.

![file-20260607121305744.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607121305744.png" | relative_url }})

As in the hook installation routine, the sample grants write permission to the first five bytes of `NtCreateUserProcess` with `NtProtectVirtualMemory`, and then restores the original bytes to remove the hook.

Because the hook function is called directly from the beginning of `NtCreateUserProcess`, the arguments set by the caller remain on the stack. The hook function uses those arguments to call the original `NtCreateUserProcess`. Immediately after `NtCreateUserProcess` returns, the main thread of `svchost.exe` has not yet started.

![file-20260605132336847.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260605132336847.png" | relative_url }})

Next, the sample prepares the PE data to be injected into `svchost.exe`. This PE data is hardcoded in the `.data` section and is first decrypted with XOR. The initial XOR key is the hardcoded value `0x38347327`, and the key is updated for each decrypted byte using calculations that involve ROR4 and ROL4 operations.

```python
def update_key(key):
    """
    mov     eax, [esp+key]
    ror     eax, 1
    not     eax
    ror     eax, 1
    sub     eax, 120h
    rol     eax, 1
    not     eax
    sub     eax, 9101h
    """
    key = u32(key)
    key = ror32(key, 1)
    key = u32(~key)
    key = ror32(key, 1)
    key = u32(key - 0x120)
    key = rol32(key, 1)
    key = u32(~key)
    key = u32(key - 0x9101)
    return key

def xor_decrypt(enc_blob, key):
    result = bytearray()
    for b in enc_blob:
        key = update_key(key)
        key_byte = key & 0xFF
        result.append(b ^ key_byte)
    return bytes(result)
```

The decrypted data is compressed with LZNT1. When it is decompressed with `RtlDecompressBuffer`, the sample obtains a byte sequence containing PE section headers and section data.

![file-20260609090620576.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260609090620576.png" | relative_url }})

Based on the section header information, the sample first maps each section into the heap of its own process. It then manually maps the PE-like second-stage data into the `svchost.exe` process and uses the inline hook on `RtlExitUserProcess` as the execution trigger. Since the PE data expects the base address `0x10000000`, the sample also performs relocation.

![file-20260607123205430.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607123205430.png" | relative_url }})

The decompressed data has the following structure. Section mapping is performed based on the array of `injection_section_header` structures. The `injection_section_header` structure contains only the important fields extracted from the PE file's `IMAGE_SECTION_HEADER` structure.

```c
struct injection_section_header // sizeof=0x11
{
	DWORD virtual_address;
	DWORD virtual_size;
	DWORD raw_address;
	DWORD raw_size;
	BYTE protection;
};

struct injection_payload_struct // sizeof=0x79
{
	int pe_original_image_base; // 0x10000000
	int const_0x0;
	int local_memory_size;
	int RtlExitUserProcessTrampoline;
	int const_0x74f8;
	int const_0x870c;
	int const_0xb000;
	int const_0x56c;
	int num_sections;
	injection_section_header section_headers[5];
	BYTE[] sections;
};
```

In addition, the sample writes the following structure data into a separate memory region in the remote process. This structure contains resolved 32-bit and 64-bit `ntdll.dll` API addresses, the first bytes of those APIs, and a 0x100-byte encrypted C2 URL list from the `.rdata` section of the sample.

```c
 struct api_struct // sizeof=0x454
 {
     QWORD ntdll32_apis_resolved;
     QWORD NtAllocateVirtualMemory;
     QWORD NtWriteVirtualMemory;
     QWORD NtProtectVirtualMemory;
     QWORD NtWaitForSingleObject;
     QWORD LdrLoadDll;
     QWORD LdrGetProcedureAddress;
     QWORD RtlExitUserProcess;
     QWORD NtCreateUserProcess;
     QWORD RtlDecompressBuffer;
     QWORD NtFlushInstructionCache;
     BYTE first_bytes_NtAllocateVirtualMemory[6];
     BYTE first_bytes_NtWriteVirtualMemory[6];
     BYTE first_bytes_NtProtectVirtualMemory[6];
     BYTE first_bytes_NtWaitForSingleObject[6];
     BYTE first_bytes_LdrLoadDll[6];
     BYTE first_bytes_LdrGetProcedureAddress[6];
     BYTE first_bytes_RtlExitUserProcess[6];
     BYTE first_bytes_NtCreateUserProcess[6];
     BYTE first_bytes_RtlDecompressBuffer[6];
     BYTE first_bytes_NtFlushInstructionCache[6];
     DWORD nulled1;
     DWORD ntdll64_apis_resolved;
     DWORD nulled2;
     QWORD NtAllocateVirtualMemory_64;
     QWORD NtWriteVirtualMemory_64;
     QWORD NtProtectVirtualMemory_64;
     QWORD NtWaitForSingleObject_64;
     QWORD LdrLoadDll_64;
     QWORD LdrGetProcedureAddress_64;
     QWORD RtlExitUserProcess_64;
     QWORD NtCreateUserProcess_64;
     QWORD RtlDecompressBuffer_64;
     QWORD NtFlushInstructionCache_64;
     BYTE first_bytes_NtAllocateVirtualMemory_64[6];
     BYTE first_bytes_NtWriteVirtualMemory_64[6];
     BYTE first_bytes_NtProtectVirtualMemory_64[6];
     BYTE first_bytes_NtWaitForSingleObject_64[6];
     BYTE first_bytes_LdrLoadDll_64[6];
     BYTE first_bytes_LdrGetProcedureAddress_64[6];
     BYTE first_bytes_RtlExitUserProcess_64[6];
     BYTE first_bytes_NtCreateUserProcess_64[6];
     BYTE first_bytes_RtlDecompressBuffer_64[6];
     BYTE first_bytes_NtFlushInstructionCache_64[6];
     DWORD nulled3;
     DWORD self;                 // ptr to api_struct data on remote process
     DWORD nulled4;
     DWORD image_base_address;
     DWORD nulled5;
     DWORD rva_import_api_struct; // 0x870c
     char curr_module_filepath[56];
     BYTE nulled6[468];
     BYTE encrypted_c2_list[256];
     DWORD cmd_p_argument_value;
 };
```

The encrypted C2 URL list is shown below and is decrypted by the second stage.

![file-20260609092525286.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260609092525286.png" | relative_url }})

### Hooking RtlExitUserProcess

The sample installs a hook on `RtlExitUserProcess` using the same approach as the hook installed on `NtCreateUserProcess`. The hook function is code contained in the PE data injected into `svchost.exe` at offset `0x7B2D`.

Because `CreateProcessA` starts `svchost.exe` without passing any arguments, the process exits immediately. During its termination routine, `RtlExitUserProcess` is called, and the second stage is executed before the termination routine completes.

# Second Stage

![file-20260610084616097.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610084616097.png" | relative_url }})

The API unhooking routine is the same as in the first stage. It grants RWX permissions to the first five bytes of `RtlExitUserProcess` with `ZwProtectVirtualMemory`, and then overwrites the hooked instruction bytes with the original bytes of `RtlExitUserProcess` stored in the `api_struct` structure written by the first stage.

![file-20260610084811444.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610084811444.png" | relative_url }})

## Configuration Decryption

The second stage decrypts the encrypted data contained in the `api_struct` structure written to the memory of `svchost.exe` by the first stage. The decryption algorithm is the same as the one used in the first stage.

![file-20260610135401627.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610135401627.png" | relative_url }})

The decrypted data contains the IDs `0x6bc4ce5` and `0x8`, which are used for later C2 communication, as well as the following C2 server URLs.

```text
albarthurst.pro
mozambiquest.pw
ransmittend.club
summerch.xyz
```

## Runtime API Resolution

The second stage resolves additional APIs on top of the APIs contained in the `api_struct` structure provided by the first stage.

First, it uses `LdrLoadDll` and `LdrGetProcedureAddress` to obtain the addresses of `LoadLibraryA` and `GetProcAddress`. Subsequent processing uses these APIs to obtain the addresses of APIs from various DLLs.

DLL names and API names are accessed through structure data like the following, with one such structure used for each API. The list of these structures exists in the third section.

```c
struct import_api_struct {
	DWORD fallback_rva_rva_api;
	DWORD nulled1;
	DWORD nulled2;
	DWORD rva_dll;
	DWORD rva_rva_api;
}
```

Using this structure, the sample obtains DLL names and API names as shown below. `rva_dll` is an offset from the image base to the DLL name. The sample accesses the DLL name using this offset and passes it to `LoadLibraryA` to load the DLL.

`rva_rva_api` is an offset to a variable that holds the API-name offset. The sample uses `rva_rva_api` to access `rva_api`, then uses `rva_api` as an offset to access the API name, and finally obtains the API address with `GetProcAddress`. The obtained API address is then stored as the value of the `rva_api` variable.

![import_api_struct.drawio.png]({{ "/assets/2026-07-28-icedid-analysis/import_api_struct.drawio.png" | relative_url }})

One important exception is that the `inet_ntoa` API is imported by ordinal rather than by API name.

As shown below, the `rva_api` value in the `import_api_struct` corresponding to `inet_ntoa` is `0x8000000C`. If this value itself were used as an offset, it would result in an out-of-range memory address.

![file-20260610170430319.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610170430319.png" | relative_url }})

When the value of `rva_api` is negative, the lower 2 bytes of the value are specified as the second argument to `GetProcAddress`. Since `0x8000000C` is negative when interpreted as a signed integer, `0xC` is passed as the argument to `GetProcAddress`.

![file-20260610170801956.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610170801956.png" | relative_url }})

The documentation for `GetProcAddress` states that the second argument can specify an API ordinal.

![file-20260610171125697.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610171125697.png" | relative_url }})

Checking the export directory of `ws2_32.dll` shows that ordinal `0xC` corresponds to `inet_ntoa`, and the address of this API is obtained.

![file-20260607101248725.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260607101248725.png" | relative_url }})

## C2 Communication

The second stage performs HTTP communication with each domain contained in the decrypted C2 list. In the initial communication, it sends data using POST, as shown below.

HTTP request:

![file-20260610105000519.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610105000519.png" | relative_url }})

POST data:

![file-20260610105056415.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610105056415.png" | relative_url }})

The first half of the HTTP request path, `"/in.php?g=2&c=06BC4CE52AB8FB7141&p=0&r=108"`, is generated from an encrypted format string, the unique ID `0x6bc4ce5` contained in the encrypted configuration, and time data obtained with `GetSystemTimeAsFileTime`.

![file-20260610131614514.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610131614514.png" | relative_url }})

The latter half, `"i=0&n=0&o=0&k=13136&a=8&l="`, is generated from the C2 list version, system uptime, the unique ID `0x8` contained in the encrypted configuration, and two unknown flags.

![file-20260610132014823.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610132014823.png" | relative_url }})

The data posted during the first connection contains the following information about the infected system.

| Data name | Data content |
| ---- | -------------------------------------------------------------------------------------- |
| `f` | URL-encoded user name obtained with `GetUserNameW` |
| `h` | URL-encoded NetBIOS name obtained with `GetComputerNameExW` |
| `b` | URL-encoded DNS host name obtained with `GetComputerNameExW` |
| `m` | Flag indicating the privileges of the current user |
| `j` | Analysis-environment detection flag |
| `u` | Encoded IP address string obtained with `GetAdaptersInfo` |
| `s` | OS and CPU information: `"<OS major version>.<OS minor version>.<OS build number>.<unknown flag 1>.<CPU bitness>.<unknown flag 2>"` |

The analysis-environment detection flag is calculated as follows.

Execution-time measurement:

The sample obtains two TSC values using the `RDTSC` instruction with only a few instructions between them. It then checks whether the difference is `0x3E8` or less. This is likely intended to detect execution delays caused by a debugger or similar analysis environment.

![file-20260610133103677.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610133103677.png" | relative_url }})

Hypervisor detection:

When the `cpuid` instruction is executed with `EAX` set to 1, bit 31 of `ECX` indicates whether a hypervisor is present. The sample checks this bit to detect a virtualized environment.

![file-20260610133530589.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610133530589.png" | relative_url }})

CPU vendor check:

When the `cpuid` instruction is executed with `EAX` set to `0x40000000`, `EBX` contains a string indicating the CPU vendor. The sample checks this string to detect a virtualized environment.

![file-20260610133358077.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610133358077.png" | relative_url }})

In this execution, the value of `j` was 7. As shown in the table below, this means that debugger detection based on the RDTSC difference, hypervisor detection, and VMware virtual machine detection were all triggered.

| Bit | Value | Meaning |
| --: | --: | ---------------- |
| 0 | 1 | Debugger detection based on RDTSC difference |
| 1 | 2 | CPUID hypervisor bit |
| 2 | 4 | VMware vendor string |

HTTP communication is performed using Windows APIs such as `WinHttpConnect`, `WinHttpOpenRequest`, and `WinHttpSendRequest`.

![file-20260610095259760.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610095259760.png" | relative_url }})

When TLS is used, the sample suppresses communication errors by configuring the connection to ignore certificate-related errors.

![file-20260610095405493.png]({{ "/assets/2026-07-28-icedid-analysis/file-20260610095405493.png" | relative_url }})

After the initial connection, the sample receives commands from the C2 server and executes the specified commands. According to the [Fortinet analysis report](https://www.fortinet.com/blog/threat-research/icedid-malware-analysis-part-two), the initial connection returns an HTTP response that prompts the malware to download a `.dat` file, and the malware continues processing based on the configuration information contained in that response.

# Conclusion

This analysis examined the flow from the first stage of the IcedID sample through execution of the second stage and C2 communication. After unpacking, the sample branches its execution path based on whether the command-line argument `-q=` is present. After re-execution, it hooks `NtCreateUserProcess` and hijacks the creation process of the `svchost.exe` process. It then decrypts and expands the encrypted and LZNT1-compressed second stage and manually maps it into the memory of the `svchost.exe` process.

A particularly notable feature is that the sample hooks `RtlExitUserProcess` and transfers control to the second stage during the termination routine of the legitimate `svchost.exe` process. This allows the malware to execute malicious code not immediately after normal process startup, but during process termination.

In the second stage, the sample uses API information and encrypted configuration data passed from the first stage to resolve additional APIs, decrypt configuration information, and communicate with C2 servers over HTTP. The decrypted configuration contains multiple C2 domains and identifiers. During the initial POST communication, the malware sends information such as the user name, host name, IP address, OS information, privilege information, and analysis-environment detection results. The analysis-environment checks include debugger detection based on timing information, hypervisor detection using CPUID, and virtual-environment detection.

Overall, this sample can be described as a multi-stage IcedID loader that combines unpacking, Heaven's Gate, API hashing, inline hooking, manual mapping, encrypted configuration data, and analysis-environment detection. In particular, the control transfers implemented through `NtCreateUserProcess` and `RtlExitUserProcess` are key to understanding the execution flow of this sample.

# IOCs

## Files

| Content              | File name | SHA256 hash                                                      |
| -------------------- | --------- | ---------------------------------------------------------------- |
| First-stage EXE file | 5.exe     | b8113a604e6c190bbd8b687fd2ba7386d4d98234f5138a71bcf15f0a3c812e91 |
| Unpacked module      |           | 358af26358a436a38d75ac5de22ae07c4d59a8d50241f4fff02c489aa69e462f |

## Network

- albarthurst[.]pro
- mozambiquest[.]pw
- ransmittend[.]club
- summerch[.]xyz

# References

- [A Deep Dive Into IcedID Malware: Part I - Unpacking, Hooking and Process Injection](https://www.fortinet.com/blog/threat-research/icedid-malware-analysis-part-one)
- [A Deep Dive Into IcedID Malware: Part II - Analysis of the Core IcedID Payload (Parent Process)](https://www.fortinet.com/blog/threat-research/icedid-malware-analysis-part-two)
