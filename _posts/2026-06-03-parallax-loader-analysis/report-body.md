# Background

Parallax is a Windows RAT designed to remotely control infected systems. According to a [Cisco Talos's report](https://blog.talosintelligence.com/coronavirus-themed-malware/), Parallax has mainly been observed in multiple campaigns since around 2020, including cases where it was distributed through emails abusing COVID-19-related themes.

The sample analyzed in this report is characterized by its use of multiple stages before executing the final payload. It decrypts PE data, shellcode, and an Imgur URL stored in the `.data` section, then injects PE into `mstsc.exe`, downloads a PNG file from Imgur site, and injects additional payloads into `cmd.exe`. It also combines multiple evasion and anti-analysis techniques, including Process Doppelgänging, Heaven's Gate, API hashing, API unhooking, AV software detection, UAC bypass, and the addition of Windows Defender exclusion settings.

Therefore, this report focuses not on Parallax RAT itself, but rather on the multi-stage loader logic, process injection, evasion techniques, and persistence mechanisms used before the RAT payload is executed.

# Execution Flow

The execution flow of this sample is shown in the figure below. The sample executes the final payload, Parallax, through multiple stages. In the 1st stage, it decrypts PE data, shellcode, and an Imgur site URL for retrieving an additional payload embedded in the initial EXE, and executes the 2nd stage inside the `mstsc.exe` process. In the 2nd stage, it downloads a PNG file from the URL and extracts shellcode and two PE files from that PNG. In the 3rd stage, the extracted PE data is executed inside the `cmd.exe` process. It then performs persistence, Windows Defender evasion, process masquerading, and finally transfers control to the Parallax RAT payload.

![Parallax.drawio 1.png]({{ "/assets/2026-06-03-parallax-loader-analysis/Parallax.drawio 1.png" | relative_url }})

# Basic Information

## Sample

File name: `para.exe`  
File type: EXE

| Type | Hash |
| ------ | ---------------------------------------------------------------- |
| MD5 | 33002b60b9e6fd6307e2eeaf2bcf78b6 |
| SHA256 | 829fce14ac8b9ad293076c16a1750502c6b303123c9bd0fb17c1772330577d65 |

## VirusTotal

| Type | Date and Time |
| ---------------- | ----------------------- |
| First submission | 2020-02-17 16:12:55 UTC |
| Last submission | 2025-07-31 09:14:00 UTC |

## Sandbox Execution Result

- [Any.run](https://app.any.run/tasks/e05812d4-4064-426f-bf39-82db78f99f9e)

# Surface Analysis

DIE identifies the sample as a Win32 EXE file built with Borland C++.

![file-20260527075421166.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260527075421166.png" | relative_url }})

The sample has an expired digital signature.

![file-20260527080232540.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260527080232540.png" | relative_url }})

# 1st Stage

The main role of the 1st stage is to decrypt the 2nd stage PE, shellcode, and the URL used to download the additional payload from the initial EXE, then execute the 2nd stage inside the legitimate process `mstsc.exe`. At this stage, it also performs defense evasion logic, including API hashing, anti-API hooking, AV software detection, and Heaven's Gate.

## Decryption of PE Data, Shellcode, and URL

Encrypted PE data and shellcode are stored in the `.data` section, and a DWORD decryption key is appended to the end of the encrypted data. The entire encrypted data blob is `0xA2B0` bytes. The first `0x1A00` bytes correspond to the PE data, and the remaining bytes correspond to the shellcode.

![file-20260601235738021.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601235738021.png" | relative_url }})

![file-20260601235843598.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601235843598.png" | relative_url }})

The decryption algorithm is a simple XOR operation using the DWORD key.

![file-20260602000418200.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260602000418200.png" | relative_url }})

The URL used by this sample to download the additional payload is also decrypted using the same key: `hxxp://i[.]imgur[.]com/emshETT[.]png`.

![file-20260601235925338.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601235925338.png" | relative_url }})

After that, the code calls offset `0x4EF0` of the decrypted PE data and shellcode. This corresponds to shellcode offset `0x34F0`.

![file-20260602000253991.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260602000253991.png" | relative_url }})

## Shellcode Execution

### API Hashing

The DLLs and APIs used by the shellcode are dynamically resolved at runtime. CRC32 is used to hash DLL names and API names.

![file-20260602004342207.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260602004342207.png" | relative_url }})

### Anti-API Hooking

Many APIs are resolved through the API hashing mechanism described above. However, for some APIs in `ntdll.dll`, the malware does not use the code from the DLL loaded at process startup. Instead, it uses APIs from an `ntdll.dll` instance dynamically loaded at runtime. This is likely intended to allow API calls while avoiding API hooks inserted by security products when the process starts.

To load `ntdll.dll`, the malware creates a file mapping object with `CreateFileMappingW` based on the file handle obtained by `CreateFileW`, and then maps the file into memory using `MapViewOfFile`.

![file-20260602004930514.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260602004930514.png" | relative_url }})

It then calculates API addresses inside this mapped `ntdll.dll` as follows:

```text
(Address of newly loaded API)
= (Address of API loaded at process startup) - (Base address of ntdll.dll loaded at process startup) + (Base address of newly loaded ntdll.dll)
```

Furthermore, to use the Heaven's Gate technique in later processing, it obtains the system call number for each API from the newly mapped `ntdll.dll`. The system call number can be obtained from the DWORD value pointed to by `(address of newly loaded API) + 1`.

![file-20260529185752864.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529185752864.png" | relative_url }})

For example, the system call number for `NtAllocateVirtualMemory` is `0x15`.

![file-20260529133123524.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529133123524.png" | relative_url }})

### AV Software Detection

The malware calls `NtQuerySystemInformation` with `SystemProcessInformation` as the first argument to obtain the list of processes on the system. It then checks whether the CRC32 hash of each process executable name matches hardcoded values.

![file-20260602075647621.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260602075647621.png" | relative_url }})

At the time of this analysis, it is unknown which product corresponds to the hardcoded hash `0x27873423`. However, Zscaler's analysis report on HijackLoader also reports a case where this hash value was used to identify AV products.

![file-20260529133847176.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529133847176.png" | relative_url }})

If AV software is detected, the malware injects PE data into another process using Process Doppelgänging instead of the normal PE injection method. The procedure is as follows:

- Create a transaction object with `ZwCreateTransaction`
- Create a new file with a random name under the TMP directory using `ZwCreateFile`
- Write the unpacked PE data to the file using `ZwWriteFile`
- Create a section based on that file using `ZwCreateSection`
- Roll back the write operation performed by `ZwWriteFile` using `ZwRollbackTransaction`
- Close the file and transaction using `ZwClose`
- Map the created section into memory with RWX permissions using `ZwMapViewOfSection`
- The PE data written by `ZwWriteFile` remains in the mapped memory, allowing the malware to inject malicious code into another process without leaving the written data on disk

If AV software is not detected, the malware performs the normal PE injection described later.

### PE Injection

The malware starts the `mstsc.exe` process in a suspended state, writes the unpacked PE data into the process memory, and then overwrites the entry point of `mstsc.exe` with a jump instruction to the written PE data. This allows it to hijack control flow using a typical PE injection technique.

It starts `C:\Windows\system32\mstsc.exe` in a suspended state using `CreateProcessW`. If this fails, it starts `cmd.exe` instead.

![file-20260527080849593.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260527080849593.png" | relative_url }})

The last `0x53A5` bytes of the shellcode contain LZNT1-compressed data. This data is decompressed using `RtlDecompressBuffer`.

![file-20260529152539422.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529152539422.png" | relative_url }})

The decompressed data is another shellcode.

![file-20260527081146024.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260527081146024.png" | relative_url }})

The malware allocates memory with RW permissions in the `mstsc.exe` process using `ZwAllocateVirtualMemory`. It writes the URL for downloading the additional payload and the shellcode decompressed by `RtlDecompressBuffer` into this memory region.

| Offset | Data                                                     |
| ------ | -------------------------------------------------------- |
| `0x0`  | Header data containing pointers to the URL and shellcode |
| `0x4C` | URL for downloading the additional payload               |
| `0x6C` | Shellcode decompressed with LZNT1                        |

![file-20260529160517643.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529160517643.png" | relative_url }})

The malware then scans the 2nd stage PE data, which was decrypted together with the currently executing shellcode, from the beginning and searches for the byte sequence `0xBBCBCBCBCB`. It overwrites the `0xCBCBCBCB` portion of the found byte sequence with the address of the memory allocated by `ZwAllocateVirtualMemory`. The byte sequence `0xBBCBCBCBCB` corresponds to the assembly instruction `mov eax, 0xCBCBCBCB`. By replacing the operand, the 2nd stage PE data can read the URL and shellcode that were previously written into memory.

Bytes in the `.text` section before modification:

![file-20260529154741674.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529154741674.png" | relative_url }})

Bytes after modification: the operand has been replaced with the memory address `0xC0000`, which was allocated by `ZwAllocateVirtualMemory`.

![file-20260529154901467.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529154901467.png" | relative_url }})

Next, the malware allocates a memory region with RWX permissions inside the `mstsc.exe` process using `ZwAllocateVirtualMemory`, and writes the `.text` and `.rdata` sections of the PE data using `ZwWriteVirtualMemory`.

![file-20260529161007336.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529161007336.png" | relative_url }})

It then obtains the entry point address from the EAX value of the main thread of `mstsc.exe` retrieved using `ZwGetThreadContext`. After granting RWX permissions to the memory region using `ZwProtectVirtualMemory`, it overwrites the code at the entry point with a jump instruction to the start address of the `.text` data written above.

![file-20260529162102784.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529162102784.png" | relative_url }})

![file-20260529162152760.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529162152760.png" | relative_url }})

Finally, by resuming the main thread of the `mstsc.exe` process with `ZwResumeThread`, execution transfers from the entry point of `mstsc.exe` to the written 2nd stage PE data, allowing the malicious code to execute.

### Heaven's Gate

When executing some APIs in `ntdll.dll`, the malware branches depending on whether the current process is a WOW64 process. It either calls the API directly or executes the API through Heaven's Gate.

![file-20260529154255278.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529154255278.png" | relative_url }})

### API Unhooking

After completing the injection into the `mstsc.exe` process, the original malware process checks the first byte of each API in the `ntdll.dll` loaded in its own memory. It does this at 500 ms intervals, up to five times. If the byte matches `0xE9` (a `jmp` instruction), it determines that API hooking has been performed and overwrites the bytes with the original API prologue obtained from the newly loaded `ntdll.dll`.

First, after executing `ZwFlushInstructionCache`, the malware reads the first byte of the API using `ZwReadVirtualMemory` and checks whether it matches `0xE9`.

![file-20260529165847611.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529165847611.png" | relative_url }})

If it matches `0xE9`, the malware temporarily grants write permissions to the first five bytes of the API instruction sequence using `ProtectMemory`, and then uses `ZwWriteVirtualMemory` to overwrite the first bytes with the first five bytes read from the newly loaded `ntdll.dll`. This allows the malware to remove the hook even if the first bytes of the API have been modified by API hooking.

![file-20260529170226583.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529170226583.png" | relative_url }})

# 2nd Stage

The main role of the 2nd stage is to access the URL for downloading the additional payload passed from the 1st stage and retrieve an additional payload disguised as a PNG file. Additional shellcode and two PE files are extracted from the retrieved PNG and eventually injected into `cmd.exe`.

## Downloading and Parsing the PNG File

The PNG file is downloaded from Imgur using a COM interface. If this method fails, the malware falls back to a download implementation using WinINet APIs such as `InternetOpenA`, `InternetOpenUrlA`, and `InternetReadFile`.

![file-20260528210202884.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260528210202884.png" | relative_url }})

In the COM-based file download procedure, the malware uses the `AddFile` and `Resume` functions of an `IBackgroundCopyJob` created by `IBackgroundCopyManager::CreateJob` to download the file from the specified URL and save it as `<random string>.png` under the `%TEMP%` directory.

![file-20260528205920024.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260528205920024.png" | relative_url }})

The saved file contains the text "BIG BROTHER IS WATCHING YOU", as shown below.

![file-20260531150238705.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531150238705.png" | relative_url }})

Using the `%TEMP%` directory path and this configuration information as arguments, the malware executes offset `0x7160` of the shellcode decompressed with LZNT1 by the 1st stage shellcode.

![file-20260529221541508.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260529221541508.png" | relative_url }})

The role of this shellcode is to parse the downloaded PNG file and obtain data containing PEs. The parsing result contains the following three data items.

| Data Type | Description                                                                                                                             |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Shellcode | Executed from the 2nd stage PE; provides analysis-environment detection and injection functionality for the 3rd stage PE into `cmd.exe` |
| PE data | Code executed inside `cmd.exe`, providing evasion functionality and related logic                                                       |
| PE data | Parallax malware body executed inside `cmd.exe`                                                                                         |

After the shellcode completes execution and control returns to the 2nd stage PE data, the malware builds a structure containing configuration information as shown below. `pe_data1` corresponds to the second row in the table above, and `pe_data2` corresponds to the third row.

```c
struct config_2nd {
	DWORD ptr_pe_data2                     // 0x0
	DWORD last_dword_of_pe_data1           // 0x4
	DWORD ptr_pe_data1                     // 0x8
	DWORD const_0x6000                     // 0xC
	DWORD const_0x4B8C                     // 0x10
	DWORD const0x1010000                   // 0x14
    DWORD ptr_str_iexplorer_exe            // 0x18
    DWORD ptr_str_cmd_exe                  // 0x1C
    DWORD ptr_startup_folder_path          // 0x20
    DWORD ptr_shellcode                    // 0x24
    DWORD const_0xF9C                      // 0x28
    DWORD nulled1                          // 0x2C
    DWORD nulled2                          // 0x30
    DWORD nulled3                          // 0x34
    DWORD const_0x10                       // 0x38
    DWORD nulled4                          // 0x3C
    DWORD const_0x100                       // 0x40
    DWORD nulled5                          // 0x44
    CHAR[0xD] str_iexplorer.exe            // 0x48
	DWORD const_0x6000                     // = size of pe_data1
	BYTE[] pe_data1
	DWORD const_0xEA77                     // = size of shellcode
	BYTE[] shellcode
	DWORD unknown
	BYTE[] pe_data2
}
```

After that, using this configuration information as an argument, it grants RWX permissions with `VirtualProtect` to the memory region containing the shellcode obtained by parsing the PNG, and jumps via a `call` instruction to offset `0xE8FC`.

![file-20260602085918993.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260602085918993.png" | relative_url }})

## Shellcode

### Analysis Environment Detection

The malware checks whether the running process is a WOW64 process using `IsWow64Process`.

![file-20260531152204749.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531152204749.png" | relative_url }})

It also checks the processor.

![file-20260531152458287.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531152458287.png" | relative_url }})

- WOW64 process and the CPU is not made by AMD → Heaven's Gate
- Otherwise → normal API calls

### AV Software Detection

The malware calls `NtQuerySystemInformation` with `SystemProcessInformation` as the first argument to obtain the process list, then checks the executable image name of each process to detect AV software. However, even if AV software is detected, the malware does not immediately terminate the process. Instead, only the branching behavior of subsequent processing changes.

There are two detection methods: direct comparison of process names and comparison of CRC32 hashes of process names.

![file-20260530114139116.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260530114139116.png" | relative_url }})

The AV products detected through string-based matching are as follows.

| Product Name | Process Name |
| ------------------- | ---------- |
| ESET Smart Security | `ekrn.exe` |
| Kaspersky AntiVirus | `avp.exe` |

The AV products detected through CRC32 hash-based matching are as follows.

| CRC32 | Product Name | Process Name |
| ------------ | ---------------------------- | ----------------------- |
| `0xb02ef94` | Avast Antivirus | `avastsvc.exe` |
| `0xc0bfbba0` | ESET Smart Security | `ekrn.exe` |
| `0x40cb21d3` | Kaspersky AntiVirus | `avp.exe` |
| `0xc0fe273f` | Symantec Event Manager | `ccsvchst.exe` |
| `0x9e0539f6` | Norton 360 | `n360.exe` |
| `0xe6ef3ab` | Avira | `avguard.exe` |
| `0x8e9e8add` | AVG Internet Security | `avgsvc.exe` |
| `0x923d5594` | AVG Internet Security | `avgui.exe` |
| `0xce1599c2` | BitDefender AntiVirus | `vsserv.exe` |
| `0x83ed98a3` | BitDefender AntiVirus | `epsecurityservice.exe` |
| `0xd50dea99` | TrendMicro AntiVirus | `coreserviceshell.exe` |
| `0x2fba3706` | McAfee Antivirus | `mcshield.exe` |
| `0x1235ed11` | McAfee Antivirus | `mctray.exe` |
| `0x3a39ba4` | Norton Internet Security | `nis.exe` |
| `0xe981e279` | Norton Internet Security | `ns.exe` |
| `0x19e8fad2` | BitDefender Antivirus | `bdagent.exe` |
| `0x64760001` | N/A | Unknown |
| `0x5f1c2fc2` | Trend Micro Security | `uiseagnt.exe` |
| `0xc68b2fd8` | ByteFence Anti-Malware | `bytefence.exe` |
| `0x8BDC7F5B` | N/A | Unknown |
| `0xefba2118` | McAfee Security Scan Plus | `mcuicnt.exe` |
| `0xfeb42b97` | Internet Security Essentials | `vkise.exe` |
| `0x6274fa64` | Comodo Internet Security | `cis.exe` |
| `0x4420ef23` | Malwarebytes Anti-Malware | `mbam.exe` |
| `0x27873423` | N/A | Unknown |

### Anti-Debugging

The malware verifies whether a debugger is attached to its own process by executing `ZwQueryInformationProcess` with the following two values as the first argument.

| Value of the First Argument | Meaning |
| --------------------------------- | ---------------------------------------------------------------------- |
| `ProcessDebugPort (0x7)` | Searches for a debug port. If a debugger is attached to the process, this value becomes `0xFFFFFFFF`. |
| `ProcessDebugObjectHandle (0x1E)` | Obtains a handle to the kernel debug object. If a debugger is attached to the process, this value becomes non-zero. |

![file-20260531155207951.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531155207951.png" | relative_url }})

If a debugger is detected, the malware does not immediately terminate the process. Instead, it causes errors by passing arbitrary invalid arguments to other APIs.

![file-20260531155749545.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531155749545.png" | relative_url }})

### PE Injection

Similar to the 1st stage, the malware performs PE injection into a `cmd.exe` process started in a suspended state. The injected code consists of the two PE data items extracted from the PNG file in the 2nd stage.

When writing the PE data, the malware does not write code into the remote process using `ZwWriteVirtualMemory`. Instead, it performs PE injection using section mapping. It maps a section created with `ZwCreateSection` into both its own process and `cmd.exe` with RWX permissions using `ZwMapViewOfSection`. By writing code to the mapped view in its own process, the code is also reflected in the `cmd.exe` process.

After that, it grants RWX permissions to five bytes starting at the entry point of `cmd.exe` using `ZwProtectVirtualMemory`, and overwrites the entry point with a jump instruction to the first PE data. This makes it possible to hijack control flow with the injected PE data when the main thread of `cmd.exe` is resumed using `ZwResumeThread`.

Original `cmd.exe` entry point:

![file-20260531174229313.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531174229313.png" | relative_url }})

Modified `cmd.exe` entry point:

![file-20260531174551920.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531174551920.png" | relative_url }})

# 3rd Stage

The main role of the 3rd stage is to establish persistence on the infected system, evade Windows Defender, disguise process information, and then transfer control to the Parallax RAT body.

## Persistence

### Startup Folder

As with the PNG download in the 2nd stage, the malware uses the `IBackgroundCopyManager` and `IBackgroundCopyJob` interfaces. In this case, however, it uses these interfaces to copy the 1st stage malware executable under the `%APPDATA%` directory.

![file-20260531195633149.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531195633149.png" | relative_url }})

It uses `IShellLinkW::SetPath` and `IPersistFile::Save` to create an LNK file for the executable above under the `%TEMP%` directory.

![file-20260602231017559.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260602231017559.png" | relative_url }})

![file-20260531201111930.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531201111930.png" | relative_url }})

This LNK file is copied to the Startup directory so that it is executed when the PC starts.

![file-20260531201306982.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260531201306982.png" | relative_url }})

### Task Scheduler

The malware uses the `ITaskScheduler` interface to create a task that executes the malware file stored under `%APPDATA%`.

![file-20260601080111253.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601080111253.png" | relative_url }})

![file-20260601080208249.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601080208249.png" | relative_url }})

## Windows Defender Evasion

If the OS of the infected system is Windows 10 or later, the malware excludes the directory containing `iexplore.exe` from Windows Defender scanning using the following command:

```powershell
powershell.exe -command "Set-MpPreference -ExclusionPath \"%s\""
```

If the OS is earlier than Windows 10, it executes the following command while using a UAC bypass technique:

```powershell
reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths\" /v \"%s\" /t REG_DWORD /d 0
```

This string is obtained by XOR-decrypting data constructed on the stack.

![file-20260601082412249.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601082412249.png" | relative_url }})

A structure containing the generated command string is passed as an argument to shellcode, and this shellcode performs a UAC bypass using a COM interface. The first `0xC70` bytes of the shellcode with SHA256 `5f6bf8db69ef5f6a03999e64df872a31f29fa026df07099301a9efc818da98b0` are copied, and execution starts from the beginning of the copied shellcode.

![file-20260601083827840.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601083827840.png" | relative_url }})

In this shellcode, `CoGetObject` is called with a moniker name containing CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` to obtain the `CCMLuaUtil` interface. This COM interface can be elevated and is used for UAC bypass.

![file-20260601223350732.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601223350732.png" | relative_url }})

The vftable of `CCMLuaUtil` is shown below. Offset `0x24` corresponds to the `ShellExec` function.

![file-20260601221001776.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601221001776.png" | relative_url }})

`CCMLuaUtil::ShellExec` is a wrapper for `ShellExecuteExW` and executes the specified command. In other words, the command decrypted above to add a Windows Defender exclusion is executed while bypassing UAC. This makes it possible to change Windows Defender settings to evade detection even from a process that does not initially have elevated privileges.

![file-20260601225203931.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601225203931.png" | relative_url }})

### Process Masquerading

The malware modifies the PEB, including rewriting the `ImagePathName` in the PEB to the path of `explorer.exe`. This is likely intended to mislead some tools that identify processes based on PEB information.

![file-20260601224545610.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601224545610.png" | relative_url }})

The destination pointed to by the PEB's `ImagePathName` is replaced.

![file-20260601224818688.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601224818688.png" | relative_url }})

![file-20260601224908461.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601224908461.png" | relative_url }})

The malware executes the entry point of the second PE data extracted from the PNG file in the 2nd stage, passing zero and the PEB as arguments. This transfers control to the Parallax malware body.

![file-20260601225356558.png]({{ "/assets/2026-06-03-parallax-loader-analysis/file-20260601225356558.png" | relative_url }})

# Conclusion

This report analyzed the multi-stage loader logic of the Parallax sample. The sample stores encrypted PE data, shellcode, and a URL for downloading an additional payload in the `.data` section of the initial executable, and decrypts them using XOR with a DWORD key. It then executes the decrypted shellcode and transfers execution to the 2nd stage by injecting a PE into the `mstsc.exe` process.

In the 2nd stage, the malware downloads a PNG file hosted on Imgur and parses it to obtain additional shellcode and two PE data items. The obtained data is eventually injected into the `cmd.exe` process, where execution proceeds to the 3rd stage. In this way, the sample abuses multiple legitimate processes in stages to execute the final Parallax body.

The sample also implements numerous evasion and anti-analysis techniques. Specifically, this analysis confirmed CRC32-based API hashing, API unhooking using a newly mapped `ntdll.dll`, Heaven's Gate, AV software process detection, Process Doppelgänging when AV software is detected, anti-debugging, and PEB rewriting for process masquerading. In addition, it uses the `CCMLuaUtil` COM interface for UAC bypass in order to add Windows Defender exclusion settings.

For persistence, the malware copies its executable under `%APPDATA%` and arranges for it to run via an LNK file in the Startup folder and via Task Scheduler. This allows the malware to continue executing even after the infected system is restarted.

Based on this analysis, defenders should monitor not only final payload hashes and URLs, but also combinations of behaviors such as suspicious suspended launches of `mstsc.exe` or `cmd.exe`, entry point modification, external file retrieval via COM interfaces, Windows Defender exclusion setting changes, and registration in the Startup folder or Task Scheduler.

This report mainly focused on the loader logic and evasion techniques used before the Parallax RAT body is executed. Future work may include additional analysis of the Parallax body executed in the 3rd stage, including its C2 communication, command handling, information-stealing capabilities, and configuration data structure.

# IOCs

## Files

| Target | Type | Hash |
| --------------------------------------- | ------ | ------------------------------------------------------------------ |
| `para.exe` | SHA256 | `829fce14ac8b9ad293076c16a1750502c6b303123c9bd0fb17c1772330577d65` |
| PE file injected into `mstsc.exe` | SHA256 | `5417b8b51a4e0ef9f021d6343715ac8c6cf7c746afcce379a8c9fb9210a621fe` |
| First PE file obtained by parsing the PNG file | SHA256 | `fe63fa5455fc77af7008cc46aa1b31e196fc294b9c1dc90169c53067a8567514` |
| First PE file obtained by parsing the PNG file (Parallax body) | SHA256 | `1b44f2857cb11f00613663131285712d906eef9d7c4e63f1be0f2a1dc0ef8e9b` |

## Network

| Type | Value | Notes |
| --- | -------------------------------------- | -------------- |
| URL | `hxxp://i[.]imgur[.]com/emshETT[.]png` | PNG for retrieving the 2nd stage |

## Registry / Commands

| Type | Value |
| -------------- | ------------------------------------------------------------------------------------------------------------ |
| PowerShell command | `powershell.exe -command "Set-MpPreference -ExclusionPath \"%s\""` |
| Registry command | `reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" /v "%s" /t REG_DWORD /d 0` |
| Registry key | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths` |

# References

- [Threat actors attempt to capitalize on coronavirus outbreak](https://blog.talosintelligence.com/coronavirus-themed-malware/)
- [Let’s Learn: Inside Parallax RAT Malware: Process Hollowing Injection & Process Doppelgänging API Mix: Part I](https://malware.news/t/lets-learn-inside-parallax-rat-malware-process-hollowing-injection-process-doppelganging-api-mix-part-i/37364)
