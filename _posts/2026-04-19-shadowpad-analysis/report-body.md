# Executive Summary

ShadowPad is a backdoor that became widely known through the 2017 supply chain attack involving NetSarang products. Since then, it has continued to appear in multiple cyber espionage campaigns believed to be linked to Chinese threat actors. Recent public research has shown that ShadowPad variants are not only used as modular backdoors, but are also protected by a dedicated obfuscation system called ScatterBrain, which makes static analysis and control flow recovery much harder. 

This report analyzes a ShadowPad loader sample that runs through DLL side-loading with a legitimately signed executable. This report explains the execution method, the obfuscation techniques, and the process used to unpack the next-stage payload. The loader DLL uses ScatterBrain-style control flow obfuscation, which makes it difficult to understand the real control flow and API call relationships through normal static analysis. In this analysis, these obfuscation layers were removed step by step, and the normalized control flow and API resolution logic were recovered.

The analysis showed that the loader DLL reads an encrypted 2nd stage payload from a tmp file, decrypts it,  and stores it in the registry. It then executes the payload inside the current process through self-injection.

Compared with existing public reports, this sample showed some changes in the pseudo-random number generation logic inside the import dispatcher and in the API resolution implementation. These differences may suggest a new ShadowPad loader variant or an operational change. This report focuses on the loader component and organizes the execution chain from initial launch to 2nd stage deployment. A detailed analysis of the deployed payload remains future work.

# Basic Information

## Sample

Sample source: [Malware Bazaar](https://bazaar.abuse.ch/sample/7ad3331be038b43c1a19066f1e4edbe85dfb08596d70774a5e15480394626d39/)  
File name: `Dvx.zip`  
File type: ZIP

| Type | Hash |
| --- | --- |
| MD5 | 43c02ac3fc7a71bb7a841ec19f53ece7 |
| SHA256 | 7ad3331be038b43c1a19066f1e4edbe85dfb08596d70774a5e15480394626d39 |

This sample was reported in a [Hunt.io](https://hunt.io/blog/state-sponsored-activity-gamaredon-shadowpad) blog post as being hosted on a ShadowPad C2 server.

IOCs for this sample were shared on X.

![file-20260325172248287.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325172248287.png" | relative_url }})

## VirusTotal

| Type | Date |
| --- | --- |
| First submission | 2025-03-20 11:08:03 UTC |
| Last submission | 2025-06-29 09:29:31 UTC |

## Sandbox Execution Results

- [Hybrid Analysis](https://hybrid-analysis.com/sample/7ad3331be038b43c1a19066f1e4edbe85dfb08596d70774a5e15480394626d39)
- [Joe Sandbox](https://www.joesandbox.com/analysis/1661013/0/html)

# Surface-Level Analysis

This sample is a ZIP archive that contains the following five files:
- `3D2DCDC2.tmp`
- `h.exe`
- `msimg32.dll`
- `AK.bat`
- `Packagec.ps1`

All files except `AK.bat` and `Packagec.ps1` are set as hidden files, but they can be displayed with the following command:
```powershell
attrib -h -s /s /d *
```

Among these files, `AK.bat` and `Packagec.ps1` are scripts used to execute the binary malware. In this report, the analysis focuses on the other three files.

First, the metadata of `h.exe` shows that it is an EXE file with the description `Amiti Antivirus Skin and Language`.

![file-20260308181417533.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260308181417533.png" | relative_url }})

It also has a valid signature from NETGATE Technologies, so it does not look malicious by itself.

![file-20260308181513694.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260308181513694.png" | relative_url }})

VirusTotal also does not detect `h.exe` itself as malicious. This suggests that `h.exe` is a host EXE used to load `msimg32.dll` from the same directory through DLL side-loading.

![file-20260308181722458.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260308181722458.png" | relative_url }})

This is consistent with Dependency Walker, which shows that `h.exe` depends on `msimg32.dll`.

![file-20260309085722867.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260309085722867.png" | relative_url }})

`msimg32.dll` is a DLL for Win64.

![file-20260308185539999.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260308185539999.png" | relative_url }})

It imports only `kernel32.dll`, has no exported functions even though it is a DLL, and contains very few meaningful strings. These characteristics strongly suggest that `msimg32.dll` is the malicious loader.

# Malware Execution Through DLL Side-Loading

Debugging `h.exe` with x64dbg shows that `msimg32.dll` is loaded by `LoadLibraryA` at offset `0xBEC6`.

When the `DllMain` function of `msimg32.dll` starts, it checks whether the bytes at offset `0xBCEC` in `h.exe` (the instruction at the return address of `LoadLibraryA`) match `"48894308"`. It then overwrites the return address that was pushed onto the stack when `LoadLibraryA` was called.

By doing this, the malware can hijack control when `LoadLibraryA` returns to `h.exe`.

![file-20260309095918401.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260309095918401.png" | relative_url }})

At this point, a DLL that has already been rewritten after control flow deobfuscation cannot run correctly because the offsets no longer match. For that reason, dynamic analysis must use the original DLL before deobfuscation.

![file-20260326204141045.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260326204141045.png" | relative_url }})

The execution flow of this sample is as follows:
```text
[ h.exe (legitimately signed EXE) ]
│
│ DLL side-loading
▼
[ msimg32.dll (malicious loader) ]
│
│ ・Hijacks control by overwriting the LoadLibraryA return address
│ ・Deobfuscation handling (ScatterBrain-style)
│ ・Dynamic API resolution
│
▼
[ 3D2DCDC2.tmp (encrypted payload) ]
│
│ ・Decryption (XOR-based)
│ ・Split storage in the registry
│ ・Overwrite the .tmp file with junk data
│
▼
[ 2nd stage payload unpacked in memory ]
│
│ ・Self-injection
│ ・Execution starts
▼
[ ShadowPad core (backdoor functionality) ]
```

# Obfuscation

As described in the [Mandiant report](https://cloud.google.com/blog/topics/threat-intelligence/scatterbrain-unmasking-poisonplug-obfuscator?hl=en), ShadowPad uses layered obfuscation based on instruction dispatchers, import dispatchers, and opaque predicates. This makes static analysis difficult if the file is left as-is.

In this analysis, I first implemented an IDAPython script to analyze the ShadowPad obfuscation techniques. I then implemented a separate Python script to export a new PE file with the obfuscation removed, using the information produced by the analysis script.

The analysis showed that this sample differs from the sample reported by Mandiant in the following ways:
- The LCG-based pseudo-random number generator used inside the import dispatcher updates its state with addition instead of subtraction.
- When resolving API addresses inside the import dispatcher, the sample uses `GetModuleHandleA` and `GetProcAddress` instead of `LoadLibraryA` and `GetProcAddress`.

For the second point, one possible reason is that `GetModuleHandleA` assumes the module is already loaded, which avoids leaving extra DLL loading traces.

## Instruction Dispatcher

The instruction dispatcher is executed through a call instruction. It uses two values to modify its own return address: a 4-byte constant stored at the original return address, and another hardcoded byte constant inside the dispatcher function. By rewriting the return address in this way, it makes the real execution flow after the dispatcher very difficult to follow.

The return address rewriting logic inside the dispatcher works as follows:
```asm
; Save registers before dispatcher execution
push regX
...
; Get the dispatcher return address
mov regX, [rsp+8]
...
; Read the hardcoded DWORD constant at the dispatcher return address
movsxd regX, dword ptr [regX]
...
; Save EFLAGS
pushfq
...
; Perform add/sub/xor and similar operations on the DWORD constant and another DWORD constant
add/sub/xor regX, imm
...
; Modify the original return address based on the result above
add/sub [rsp+10h], regX
...
; Restore EFLAGS
popfq
...
; Restore saved registers
pop regX
...
; Jump to the rewritten return address
retn
```

By stacking these dispatchers many times before the real code executes, the malware heavily distorts the control flow of the whole ShadowPad loader.

In addition, the dispatcher functions themselves are protected by anti-disassembly techniques based on opaque predicates, which makes static analysis even harder. For example, two opposite jcc instructions such as `ja` and `jbe` are placed with one instruction between them. This causes code that can never be executed to still be disassembled in IDA, which hides the real control flow.

![file-20260309111550964.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260309111550964.png" | relative_url }})

One example of the control flow shown in IDA is below. It contains many blocks that are never actually executed, which hides the true flow.

![file-20260309113636914.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260309113636914.png" | relative_url }})

## Import Dispatcher

By checking the API calls made by this sample in a sandbox or debugger, it is clear that it performs dynamic API resolution through `GetModuleHandleA` and `GetProcAddress`.

I traced the instructions executed between two `GetProcAddress` calls in x64dbg and removed unrelated instructions such as instruction dispatcher code. This showed the following API resolution and execution flow:
```asm
; Call into the import dispatcher
0x0000000180010CD9 call qword ptr ds:[0x000000018001A256]

; Store a pointer to the API-resolution structure in rcx
; Save register values
0x000000018000E2A9 push rcx
0x000000018000E2AA lea rcx, ds:[0x000000018001A11F]
0x0000000180013AF4 push rdx
0x0000000180013AF5 push r8
0x000000018000F784 push r9
0x00000001800116CD push rbx

; Decryption code stores the DLL name at [rsp+0x130]
; Decryption code stores the API name at [rsp+0x20]

; Call GetModuleHandleA with the decrypted DLL name
0x0000000180014510 lea rcx, ss:[rsp+0x130]
0x000000018000F168 call rax

; Call GetProcAddress with the DLL base and API name
0x000000018000E526 mov rdx, r12
0x000000018000E529 mov rcx, r11
0x000000018000FA9D call rax

; Restore saved registers
0x0000000180011D94 pop rbx
0x0000000180015907 pop r9
0x0000000180015909 pop r8
0x000000018001590B pop rdx
0x000000018000D8AD pop rcx
0x000000018001416C pop rax

; Call the resolved API
0x000000018000FA9D call rax
```

The import dispatcher is executed through `call [rip+disp32]` or `jmp [rip+disp32]`, and each import dispatcher corresponds to one API.

![file-20260313112954823.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260313112954823.png" | relative_url }})

It then decrypts the DLL name and API name using the algorithm described below, and resolves the needed API address through `GetModuleHandleA` and `GetProcAddress`.

Finally, the API is executed with `call rax`, and the import dispatcher ends.

### Decryption of DLL Names and API Names

A pointer to the structure data used to decrypt the DLL name and API name is hardcoded inside the dispatcher function and loaded with `lea rcx, <addr>`.

![file-20260313114112425.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260313114112425.png" | relative_url }})

The data used for API resolution has the following structure:
```c
// Fields used to decrypt DLL and API names,
// plus a field that stores the resolved API address once it has been resolved.
struct protected_import {
	encrypted_name* dll_name;
	encrypted_name* api_name;
	PVOID          resolved_api;
}

// Data used to decrypt either the DLL name or the API name
struct encrypted_name {
	DWORD   seed;       // Seed for the pseudo-random generator used in decryption
	BYTE[1] encrypted;  // Encrypted DLL name or API name
}
```

When the import dispatcher is called, it first checks the `resolved_api` field of the `protected_import` structure to see whether the API has already been resolved. Only if it is unresolved does it decrypt the DLL name and API name by XORing the encrypted data with pseudo-random bytes generated by an LCG-based algorithm.

The internal state of the pseudo-random generator used by this sample is 4 bytes. It is initialized from the seed inside the `encrypted_name` structure. The state is then updated for each byte of encrypted data with the following formula:

$$
X_{n+1} = \mathit{0x11} * X_n + \mathit{0x80FF8FE} \;(mod\; 2^{32})
$$

After each update, the key is calculated as the sum of the four bytes of the updated state. That key is XORed with one byte of the encrypted data. This process repeats until the full ciphertext is decrypted.

Google's report stated that subtraction was used in the state update, but in this sample addition is used, as shown above.

The following Python code summarizes the DLL/API name decryption logic:
```python
class Decryptor:
    def __init__(self, seed, src):
        self.seed = seed
        self.src = src

    def decrypt(self):
        dst = bytearray()
        state = self.seed
        for i in range(0x400):
            state = (state * 0x11 + 0x80ff8fe) & 0xFFFFFFFF

            key = (((state >> 24) & 0xFF) + ((state >> 16) & 0xFF) + ((state >> 8) & 0xFF) + (state & 0xFF)) & 0xFF
            res = key ^ self.src[i]
            if not res:
                break
            dst.append(res)

        return bytes(dst)

def main():
    enc_struct_ea = 0x18001A81D
    seed = read_dword(enc_struct_ea)
    src = read_bytes(enc_struct_ea + 4, 0x400)
    decryptor = Decryptor(seed, src)
    decrypted = decryptor.decrypt()
    print(decrypted.decode()) # "Kernel32.dll"
```

### Decryption Results

In this sample, a total of 84 APIs are executed through the import dispatcher.

```text
CloseHandle
VirtualProtect
RegOpenKeyExW
RegFlushKey
lstrlenW
GetCurrentProcessId
ExitProcess
CloseHandle
GetLastError
RegQueryValueExW
QueryDosDeviceW
ExitThread
GetLastError
QueryPerformanceCounter
lstrlenW
GetLastError
EnterCriticalSection
DeleteCriticalSection
CreateFileW
LeaveCriticalSection
VirtualProtect
lstrlenW
WaitForMultipleObjects
LeaveCriticalSection
GetVolumeInformationW
QueryPerformanceCounter
GetLastError
lstrlenA
WriteFile
CloseHandle
RegCloseKey
GetLastError
GetFileSizeEx
RegSetValueExW
VirtualAlloc
GetProcAddress
CreateFileW
CreateThread
wsprintfW
LeaveCriticalSection
GetLogicalDriveStringsW
CloseHandle
lstrlenW
GetModuleFileNameW
CloseHandle
LocalFree
CloseHandle
EnterCriticalSection
GetModuleHandleW
GetLastError
GetSystemDirectoryW
RegCreateKeyExW
GetLastError
ReadFile
GetMappedFileNameW
ResetEvent
RegCloseKey
CreateEventW
GetModuleHandleW
WaitForSingleObject
GetLastError
wsprintfW
GetModuleHandleW
EnterCriticalSection
SetEvent
wsprintfW
SetEvent
InitializeCriticalSection
DeleteCriticalSection
GetCurrentProcess
WideCharToMultiByte
InitializeCriticalSection
lstrlenW
SetLastError
MultiByteToWideChar
GetLastError
GetLastError
CreateEventW
GetFileTime
WaitForSingleObject
GetProcAddress
GetModuleHandleW
GetProcAddress
LocalAlloc
```

## Opaque Predicate

Inside the instruction dispatcher, the control flow is obfuscated by placing jcc instructions with opposite meanings close together. Similar opaque predicate based anti-disassembly techniques are also used throughout the rest of the binary.

These techniques abuse the behavior of static analysis tools such as IDA, which try to disassemble both branches of a jcc instruction. As a result, code that can never actually execute is still disassembled. This makes the control flow look much more complex and also blurs the boundary between code and data.

This sample uses the following three types of opaque predicate patterns.

### Back-to-back jcc instructions

Two jcc instructions with the same condition are placed one after another. The second jcc is never executed, but its branch target is still disassembled.

![file-20260319191001452.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260319191001452.png" | relative_url }})

### `test reg, 0`

A jcc instruction is placed after `test reg, 0`. Because `test reg, 0` always sets `ZF=1`, the branch outcome is fixed, but both branch targets are still disassembled.

![file-20260319191137430.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260319191137430.png" | relative_url }})

### `cmp rsp, imm`

A jcc instruction is placed after `cmp rsp, imm`. The constant `imm` is chosen to be clearly too small or too large to match the real stack pointer value at that point, so the branch result is effectively fixed. However, disassemblers such as IDA do not recognize that only one path is possible, so both paths are disassembled.

# Deobfuscation

I created a Python tool to remove the ScatterBrain-style control flow obfuscation used in ShadowPad and to reconstruct a statically analyzable PE file: [deobf_shadowpad](https://github.com/argoFY/deobf_shadowpad)

The target obfuscation includes indirect control flow transitions through instruction dispatchers, protected API calls through import dispatchers, and branch noise introduced by opaque predicates.

This implementation follows [Mandiant's deobfuscation script](https://github.com/mandiant/poisonplug-scatterbrain), but it has one notable difference: it is split into the following two stages:
1. Analyze obfuscated instruction dispatchers, import dispatchers, and opaque predicates in IDA Pro, and generate normalized function information in JSON format.
2. Reconstruct a deobfuscated PE from the JSON file generated in stage 1.

This separation was designed with the following goals:
- Clearly separate the responsibilities of analysis and reconstruction
- Make it easier to inspect how instruction dispatchers, import dispatchers, and opaque predicates were analyzed in IDA, which helps when adapting to variants
- Make the JSON file usable as evidence of the deobfuscation process
  - Which instruction dispatcher jumps to which address
  - Which import dispatcher corresponds to which API
  - The normalized instruction stream for each function
  - Branch targets, call targets, and RIP-relative references for each instruction

## Overall Processing Flow of the Scripts

The processing flow of the scripts is as follows:
1. Map instruction dispatchers to their real destination addresses
	1. Scan the full executable sections and extract candidate instruction dispatcher calls
	2. Verify the instruction patterns of dispatcher candidates and resolve the real branch target through emulation
2. Map import dispatchers to the APIs they call
	1. Extract import dispatcher entries in the form of `call [rip+disp32]` or `jmp [rip+disp32]`
	2. Decrypt the protected DLL names and API names
3. Reconstruct the original control flow graph with a depth-first search using the resolved instruction dispatchers and import dispatchers
	1. When an opaque predicate is found, continue analysis only along the path that can actually execute
4. Export the normalization result as an intermediate JSON representation
5. Read the JSON file in a separate script, relocate the code section, and add the APIs invoked through import dispatchers to the ILT/IAT of the original PE in order to reconstruct a deobfuscated PE

## Role of Each Module

### `resolve_dispatcher.py`

This module detects instruction dispatcher calls and resolves their real jump targets. It scans the full executable sections and finds candidate call instructions through byte-pattern matching. Candidates that match the characteristic instruction patterns of the dispatcher are then selected.

Next, it emulates execution of the full dispatcher function by using [flare-emu](https://github.com/mandiant/flare-emu), and identifies the actual destination reached by the final `retn` instruction.

This allows the tool to map an obfuscated `call dispatcher` transition to the real destination address.

### `resolve_import.py`

This module resolves import dispatchers. It extracts candidate `call [rip+disp32]` and `jmp [rip+disp32]` instructions used to enter import dispatchers, follows their execution flow, and checks whether they eventually reach `lea rcx, <protected_import address>`. If they do, it decrypts the contents of the `protected_import` structure described earlier and identifies the real DLL name and API name.

These results are later used during PE reconstruction to build an ILT/IAT that includes the APIs called through import dispatchers, and to replace import dispatcher calls with direct API calls.

### `recover_cfg.py`

This module reconstructs the control flow of obfuscated functions and converts them into normalized instruction streams. Its processing has two stages:
1. Control flow recovery with the `recover_recursive` function
2. Control flow normalization with the `normalize_function` function

During recovery, it recursively explores all reachable blocks from a given function while identifying resolved instruction dispatchers, resolved import dispatchers, opaque predicates, normal jmp/jcc instructions, and ordinary call instructions.

During normalization, it removes redundant instructions that were inserted by instruction dispatchers, import dispatchers, and opaque predicates, and generates a linear instruction stream that contains only the real control flow of each function.

It also preserves the following information for each instruction so that it can be used after code relocation:
- Branch target
- Fallthrough target
- Call target
- Byte sequence of the condition part of jcc instructions
- RIP-relative data reference information

### `rebuild_pe_export.py`

This module converts the analysis results into an intermediate representation that can be used by the builder that generates the deobfuscated PE, and exports it in JSON format. In this representation, addresses are stored as VAs instead of RVAs so that the addresses observed in IDA can be used directly as canonical keys. Image-base-dependent conversions are intentionally kept inside the PE builder, described below.

### `rebuild_pe.py`

This is the PE reconstruction script that runs outside IDA, implemented with [Miasm](https://github.com/cea-sec/miasm). It reads the JSON data that contains the intermediate analysis results and performs the following steps:
- Place normalized functions into a new code section
- Fix RIP-relative call / jump / jcc targets and data references based on the relocated code addresses
- Build a new ILT/IAT that merges existing imports with the APIs called through import dispatchers
- Rewrite references that still point to the old IAT so that they point to the newly created IAT
- Update the PE header, import directory, IAT directory, and related structures as needed

As a result, the script generates a new PE file with cleaner code sections and consistent import information, making static analysis much easier.

# Analysis of the Deobfuscated DLL

After deobfuscation, the sample is clearly a loader that behaves as follows:
- Reads an encrypted 2nd stage payload from the temporary file `3D2DCDC2.tmp`
- Decrypts the payload and adds runtime context and local file contents
- Re-encrypts the data with a machine-specific key and stores it in the registry
- Reloads the payload from the registry and decrypts it again
- Copies the decrypted payload into executable memory and runs it inside the current process

## Function Execution Through Worker Threads

This sample executes many functions through worker threads. By turning function calls into queued jobs, the true call relationships do not appear directly in the call stack, which makes control flow tracing harder during analysis.

Jobs are defined with the following structure. The target function is specified by a function pointer. Up to 10 arguments can be passed, and the return value is stored as a DWORD.

```c
00000000 struct worker_job_struct // sizeof=0x68
00000000 {
00000000     HANDLE completion_event;         // Event used to signal job completion
00000008     worker_job_callback_t callback;  // Callback function
00000010     __int64 args[10];                // Function arguments
00000060     unsigned int result;             // Function return value
00000064     DWORD submit_tick;
00000068 };
```

First, the `sub_180026b0` function creates 10 worker threads.

![file-20260325183339812.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325183339812.png" | relative_url }})

It then creates a job queue with the following structure:
```c
00000000 struct worker_job_queue_struct // sizeof=0xA0
00000000 {
00000000     HANDLE worker_threads[10];    // Worker thread list
00000050     HANDLE has_jobs_event;
00000058     worker_job_list pending_jobs; // Linked list of queued jobs
00000090     volatile LONG queue_refcount;
00000094     LONG reserved2;
00000098     DWORD (*pGetTickCount)();
000000A0 };
```

Each worker thread runs an infinite loop. It checks the job queue, pulls a job when one arrives, and then executes it.

![file-20260325190708481.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325190708481.png" | relative_url }})

The `sub_180026b0` function is used to register execution of a given function as a job. After creating a `worker_job_struct`, it notifies the worker threads of the new job with `SetEvent`.

![file-20260325154532733.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325154532733.png" | relative_url }})

## String Decryption

The DLL names, API names, and format strings used by this sample are hidden by encryption. The decryption algorithm is based on a hardcoded seed-derived key, a per-round key update, and XOR-based decryption.

For example, the decryption function used to recover the format string for generating the temporary file name is called with several 4-byte immediate values as arguments.

![file-20260325192646941.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325192646941.png" | relative_url }})

The following Python code represents the decryption algorithm used by `mw_decrypt_str (sub_180024A60)`:
- The first argument is used as `seed_dword` for key generation, and the remaining arguments are treated as ciphertext data in `data_dwords`
- The plaintext length is the lower 2 bytes of `seed_dword ^ ((HIWORD(seed_dword) + 1823) & 0xFFFF)`
- The seed used for decryption key generation is the upper 2 bytes of `seed_dword`, combined with the hardcoded value `0xCAB1071F`
- The ciphertext is decrypted by XOR with a 4-byte key, and the key is updated every 4 bytes by subtracting the hardcoded value `0x3EC9F0FC`

```python
INITIAL_STATE = 0xCAB1071F
STREAM_DELTA = 0x3EC9F0FC

def decrypt_mw_string(seed_dword: int, data_dwords: list[int]) -> bytes:
    encoded_size = u32(seed_dword ^ (((seed_dword >> 16) + 1823) & 0xFFFF)) & 0xFFFF
    needed_dwords = (encoded_size + 3) // 4
    if len(data_dwords) < needed_dwords:
        raise ValueError("not enough dwords")

    rolling_key = INITIAL_STATE

    for seed_byte in ((seed_dword >> 16) & 0xFF, (seed_dword >> 24) & 0xFF):
        mixed = u32(rolling_key + seed_byte)
        rolling_key = u32((mixed << 8) | (mixed >> 24))

    out = bytearray()

    for i in range(encoded_size // 4):
        rolling_key = u32(rolling_key - STREAM_DELTA)
        out.extend(struct.pack("<I", u32(data_dwords[i]) ^ rolling_key))

    tail = encoded_size & 3
    if tail:
        rolling_key = u32(rolling_key - STREAM_DELTA)
        out.extend(struct.pack("<I", u32(data_dwords[encoded_size // 4]) ^ rolling_key)[:tail])

    return bytes(out)
```

Decrypted strings include the following:
```text
%8.8X
%8.8X.tmp
SOFTWARE
NTDLL.DLL
memcpy
memset
_wcsnicmp
GetTickCount
KERNELBASE
KERNEL32
```

## Decryption of the 2nd Stage Payload

The path of the `.tmp` file that contains the encrypted 2nd stage payload is derived from the DLL timestamp and hardcoded constants as follows:
```c
staging_id = 
(((pe_timestamp * 0x1FFF) - 0x51AC75A9) * 0x1FFFF - 0x18F7D284) & 0xFFFFFFFF;
wsprintfW(tmp_filename, "%8.8X", staging_id);
```

The content of the encrypted `.tmp` file is structured as follows:

| Offset | Size | Content |
| --- | --- | --- |
| 0x0 | Variable | Encrypted data |
| End - 0x4 | 0x4 | Seed used to decrypt the data |

The decryption algorithm is the same as the one used for string decryption.

![file-20260325162114283.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325162114283.png" | relative_url }})

The decrypted data is 64-bit shellcode.

![file-20260327090110580.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260327090110580.png" | relative_url }})

Its control flow is obfuscated in the same way as `msimg32.dll`.

![file-20260327090202057.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260327090202057.png" | relative_url }})

## Storage of the 2nd Stage Payload

Next, the decrypted 2nd stage payload is stored in the registry. This is not intended as persistence through a Run key or similar mechanism. Instead, it appears to be a defense evasion technique that avoids leaving the payload in plaintext on disk by storing it in encrypted form in the registry. The original `.tmp` file is overwritten with junk data.

The loader appends the following metadata to the decrypted data:
- Block tag = `<metadata size> - 0x50000000`
- Constant value 3 (likely representing the current operating mode)
- DLL timestamp
- Target registry path
- Host EXE file path used for DLL side-loading
- DLL file path
- `.tmp` file path

It also appends the full contents of the host EXE, the loader DLL, and the `.tmp` file in encrypted form:
- Host EXE block tag = `<size of encrypted host EXE> - 0x4F000000`
- Encrypted host EXE data
- Seed used to encrypt the host EXE data
- Loader DLL block tag = `<size of encrypted loader DLL> - 0x4E000000`
- Encrypted loader DLL data
- Seed used to encrypt the loader DLL data

The encryption seed is generated with `QueryPerformanceCounter` as shown below.

![file-20260326085432140.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260326085432140.png" | relative_url }})

The full data blob is then encrypted with a host-specific key. The seed used for this encryption is generated as follows, and the same XOR-based algorithm is used as in decryption:

```text
machine_key = volume_serial_number ^ pe_timestamp ^ 0xE9BA6677;
```

The destination registry key for the 2nd stage payload has the format `"SOFTWARE\<generated>\<generated>"`. In `sub_180025390`, the string `"SOFTWARE"` is obtained by decryption, and the remaining parts are generated from the DLL timestamp.

![file-20260326090004303.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260326090004303.png" | relative_url }})

In this sample, the destination paths are:
- `HKLM\SOFTWARE\RsXchinsx\DiJotyzej`
- `HKCU\SOFTWARE\RsXchinsx\DiJotyzej`

The malware first tries to store the data under `HKLM`, and if that fails, it falls back to `HKCU`.

As shown below, writes of binary data to the registry under `HKLM\SOFTWARE\RsXchinsx\DiJotyzej` can be observed.

![file-20260326113547975.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260326113547975.png" | relative_url }})

The data is stored as split `REG_BINARY` chunks of up to `0xEDD` bytes each. Each value name is generated from the offset of the corresponding chunk.

![file-20260325164655906.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325164655906.png" | relative_url }})

After the registry write finishes, the original `.tmp` file is overwritten with 1 MiB of junk data.

## Execution of the 2nd Stage Payload Through Self-Injection

Finally, the `sub_1800254dd` function injects the 2nd stage payload, loaded from and decrypted from the registry, into the current process.

It allocates RW memory with `VirtualAlloc`, copies the 2nd stage payload to a random offset inside that region, and then changes the memory permission to RX with `VirtualProtect` in `sub_180024f40` to make it executable. The random offset is generated with `QueryPerformanceCounter`.

![file-20260325170541351.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325170541351.png" | relative_url }})

The 2nd stage payload unpacked in this way is executed at the end of `DllMain`, transferring control to the next stage.

![file-20260325170852710.png]({{ "/assets/2026-04-19-shadowpad-analysis/file-20260325170852710.png" | relative_url }})

# Conclusion

This report analyzed the ShadowPad loader and clarified its execution flow and internal behavior. The sample starts through DLL side-loading with a legitimately signed executable, and the loaded DLL uses a distinctive initial execution method in which it hijacks control by overwriting the return address of `LoadLibraryA`.

Inside the loader, ScatterBrain-style control flow obfuscation and encrypted API names make static analysis difficult. To handle this, I identified instruction dispatchers, API dispatchers, and opaque predicates, and reimplemented the decryption logic. This made it possible to recover the API resolution process and the logic used to deploy the next stage. During this work, several differences from previously published reports were also observed.

The loader decrypts an encrypted payload stored in an external file, stores it in split form in the registry, and then executes the 2nd stage payload in memory through self-injection. It also makes heavy use of worker-thread-based function execution throughout the process, which helps hide the real call relationships and makes call stack tracing harder.

The next step is a detailed analysis of the 2nd stage payload deployed by this loader.

# Tools and Libraries Used in the Analysis

- IDA (v9.3)
- x64dbg (Aug 19 2025)

# References

- [Updated Shadowpad Malware Leads to Ransomware Deployment](https://www.trendmicro.com/en_us/research/25/b/updated-shadowpad-malware-leads-to-ransomware-deployment.html)
- [State-Sponsored Tactics: How Gamaredon and ShadowPad Operate and Rotate Their Infrastructure](https://hunt.io/blog/state-sponsored-activity-gamaredon-shadowpad)
- [ScatterBrain: Unmasking the Shadow of PoisonPlug's Obfuscator](https://cloud.google.com/blog/topics/threat-intelligence/scatterbrain-unmasking-poisonplug-obfuscator?hl=en)
- [Follow the Smoke: China-nexus Threat Actors Hammer At the Doors of Top Tier Targets](https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/)
