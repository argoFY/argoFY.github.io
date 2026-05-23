# Background

Ardamax is a malware family that originates from a commercial keylogger and monitoring tool for Windows. It was originally provided as software for monitoring user activity on a machine, but it has also been abused by attackers for credential theft and user surveillance.

The main capabilities of Ardamax include recording keystrokes, collecting active window titles, capturing clipboard data, taking screenshots, saving log files, and exfiltrating the collected data. It is especially known for its keylogging capability and is commonly used to steal account names and passwords entered in web browsers, email clients, business applications, and other software.

# Execution Flow

The execution flow of this sample is shown below.

![file-20260521223504656.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260521223504656.png" | relative_url }})

# Basic Information

## Sample

Source: [MalwareBazaar](https://bazaar.abuse.ch/sample/8c870eec48bc4ea1aca1f0c63c8a82aaadaf837f197708a7f0321238da8b6b75/)  
File name: `example.exe`  
File type: EXE

| Type | Hash |
| --- | --- |
| MD5 | e33af9e602cbb7ac3634c2608150dd18 |
| SHA256 | 8c870eec48bc4ea1aca1f0c63c8a82aaadaf837f197708a7f0321238da8b6b75 |

## VirusTotal

| Type | Date |
| --- | --- |
| First submission | 2013-05-31 20:41:36 UTC |
| Last submission | 2026-05-19 07:44:32 UTC |

# Initial Triage

A large portion of the file consists of overlay data. The entropy of the overlay payload is also very high, at 7.99.

![file-20260519081542818.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519081542818.png" | relative_url }})

DIE identifies the overlay as zlib-compressed data.

![file-20260519081611617.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519081611617.png" | relative_url }})

## Overlay

When the overlay is inspected with HxD, it starts with `78 DA`, indicating that it is zlib-compressed data. Another zlib-compressed stream is also present 0x400 bytes after the start of the first zlib header.

![file-20260519084213020.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519084213020.png" | relative_url }})

![file-20260520214520298.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520214520298.png" | relative_url }})

The following Python script can be used to decompress the overlay data. The decompressed result contains another PE file.

```python
import zlib

filepath = "..\\ardamax.bin"
with open(filepath, "rb") as f:
    data = f.read()

overlay_payload = data[0x3A00:]
decompressed = zlib.decompress(overlay_payload)

filepath = "..\\ardamax_decompressed_overlay.bin"
with open(filepath, "wb") as f:
    f.write(decompressed)
```

![file-20260519084304232.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519084304232.png" | relative_url }})

DIE identifies this PE file as a Win32 DLL. Its size is also small, only 4 KiB.

![file-20260519084431169.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519084431169.png" | relative_url }})

The entropy of this PE file is low, suggesting that it is not packed.

![file-20260519084401965.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519084401965.png" | relative_url }})

This DLL exports only one function, named `sfx_main`.

![file-20260519084704187.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519084704187.png" | relative_url }})

# Dynamic Analysis with CAPEv2 Sandbox

During dynamic analysis, DNS resolution for `smtp.mail.yahoo.com` was observed. This suggests that the sample has an email-sending capability.

![file-20260519091622618.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519091622618.png" | relative_url }})

The file `DPBJ.exe` had a different hash from the PE files observed up to this point, indicating that it is a separate file.

![file-20260519092047541.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519092047541.png" | relative_url }})

Data whose hash matched the PE file decompressed from the zlib stream was saved as a `.tmp` file.

![file-20260519091907318.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519091907318.png" | relative_url }})

In addition, multiple `.jpeg` files containing screenshots of the PC screen were newly created under `C:\Windows\SysWOW64\28463`. This indicates that the sample includes screenshot-capturing functionality.

# DLL File Extraction

The sample creates two `.tmp` files from its own overlay data. The file names are generated using `GetTempFilePathW`. The second argument of `GetTempFilePathW` is set to `"@"`, which causes the generated `.tmp` file names to always start with `"@"`. In this analysis, the files `"@2E71.tmp"` and `"@2E81.tmp"` were created.

The sample then loads the first file, `@2E71.tmp`, with `LoadLibraryW`, obtains the address of its `sfx_main` function, and executes `sfx_main` with a structure containing the paths of the two `.tmp` files as an argument.

![file-20260521212545056.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260521212545056.png" | relative_url }})

# Analysis of `sfx_main`

The `sfx_main` function extracts various data from the other `.tmp` file, `"@2E81.tmp"`, and saves or executes the extracted data as files.

After setting the file pointer to the beginning of the overlay data, the function performs the following operations in each iteration:

1. It reads 0x210 bytes with `ReadFile` and extracts the string at the beginning of the buffer. This string is used as the output file name for the extracted data. In the example shown below, the file name is `"DPBJ.001"`.
2. It reads the last two DWORD values from the 0x210-byte buffer. In the example below, the values are 0x3 and 0x1ec. The last DWORD is a flag that determines the directory where the extracted file is placed. The second DWORD from the end represents the size of the data read in step 3. The meanings of the flags are summarized in the table below.
3. It reads additional data with `ReadFile` according to the size specified by the second DWORD from the end.

| Flag condition | Meaning |
| --- | --- |
| `(flag & 2) != 0` | If the first byte of `@2E81.tmp` is 1, the file is placed under the directory returned by `GetWindowsDirectory`. Otherwise, it is placed under the directory returned by `GetSystemDirectory`. |
| `(flag & 2) == 0` | The file is placed under the temporary directory returned by `GetTempPathW`. |
| `(flag & 4) != 0` | The saved file is executed using `ShellExecuteW`. |

Example of the 0x210-byte data read in step 1:

![file-20260519234217790.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519234217790.png" | relative_url }})

Example of the data read in step 3. The red boxes show the two DWORD values referenced in step 2.

![file-20260519235344976.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260519235344976.png" | relative_url }})

Among the files created by this process, `DPBJ.exe` is created with a flag value of 0x6. Because of this flag, it is executed through `ShellExecute` with the `open` operation.

![file-20260520091256536.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520091256536.png" | relative_url }})

In this sample, the following files were extracted by this process.

| File name | Description |
| --- | --- |
| `DPBJ.exe` | EXE file executed from the `sfx_main` function via `ShellExecuteW` |
| `DPBJ.001` | Data file containing encrypted configuration information for `DPBJ.exe` |
| `DPBJ.006` | DLL used by `DPBJ.exe`; provides features such as keylogging |
| `DPBJ.007` | DLL used by `DPBJ.exe`; provides evasion functionality |
| `key.bin` | Data file likely containing the Ardamax license key |
| `ALK.exe` | Not used in this sample; its role remains unknown |

# Analysis of DPBJ.exe

## Initial Triage

`DPBJ.exe` is a Win32 EXE file. DIE identifies it as being protected by ASProtect and NTkrnl Protector.

![file-20260520093816068.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520093816068.png" | relative_url }})

The file contains multiple unnamed sections, and all sections except the `.rsrc` section have very high entropy.

![file-20260520093939890.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520093939890.png" | relative_url }})

All sections have RWX permissions, suggesting that the program may perform self-modification at runtime.

![file-20260520094222661.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520094222661.png" | relative_url }})

The resource data contains strings that suggest FTP communication, keylogging, clipboard-saving functionality, and other features.

![file-20260520094503888.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520094503888.png" | relative_url }})

![file-20260520094543223.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520094543223.png" | relative_url }})

The resource data also contains strings indicating that this sample belongs to the Ardamax family.

![file-20260520094836314.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520094836314.png" | relative_url }})

## Unpacking

The entry point uses ROP-like control-flow hiding. First, the value 0x493001 is pushed onto the stack, and a function is called.

![file-20260520112440101.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520112440101.png" | relative_url }})

This function simply executes `retn`, which transfers execution to the `retn` instruction at 0x40100A.

![file-20260520112607057.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520112607057.png" | relative_url }})

At this point, the top of the stack contains 0x493001, which was pushed before the function call. Therefore, the `retn` instruction jumps to 0x493001.

The destination also uses an anti-disassembly technique based on a rogue byte. As shown below, an unnecessary byte, 0xE9, is inserted after a `call` instruction, causing IDA to disassemble the code incorrectly.

![file-20260520112722820.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520112722820.png" | relative_url }})

This sample expands its real code by overwriting its own EXE image through process hollowing. To identify the OEP after unpacking, a breakpoint was set on execution from the memory region where the original EXE image was mapped. After identifying the OEP, Scylla was used to fix the import table and dump the unpacked PE.

When the dumped PE file was inspected, additional imports from `wininet.dll` and `ws2_32.dll`, which provide networking functionality, were present.

![file-20260520194045915.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520194045915.png" | relative_url }})

## Overview

This EXE file provides information-stealing functionality focused on monitoring user activity, storing logs, and exfiltrating collected data through multiple channels. It collects not only keyboard input but also window information, web-related information, chat-related information, clipboard contents, and other data. The collected data is saved locally and then exfiltrated using SMTP, FTP, or a network share.

Configuration information such as the exfiltration destination is stored in encrypted form in `DPBJ.001`. `DPBJ.exe` reads this configuration file and uses it to configure its behavior. It also loads additional plugins, `DPBJ.006` and `DPBJ.007`, with `LoadLibraryW` and executes their exported functions.

In this sample, log generation and exfiltration are separated. The stolen data is first saved to local files and then exfiltrated using the configured method. This design enables the same stolen data to be exfiltrated through SMTP, FTP, or a shared folder, providing operational flexibility.

## Decrypting the Configuration in DPBJ.001

The configuration information for the exfiltration functionality is loaded from `DPBJ.001`. This configuration file is encrypted with XOR. The XOR key is derived from the first four bytes of the hardcoded ASCII string `"65C9CF3EF6B64C999D70A33ACFB95933"`, interpreted as a hexadecimal value. This results in the key value 0x65C9.

After decrypting the extracted configuration file, it was confirmed that this sample is mainly configured to use the SMTP path.

- Recipient email address: `linux06400@yahoo.com`
- SMTP server: `smtp.mail.yahoo.com`
- SMTP port: 587
- User name: `linux06400@yahoo.com`
- Password: `azerty/06`

## Data Exfiltration Functionality

The core exfiltration logic is implemented in `sub_0040DE91`. This function switches between three exfiltration paths according to configuration flags: SMTP, FTP, and network share. This is one of the most important characteristics of this sample because it does not rely on a single communication channel.

In the SMTP path, locally generated logs are assembled into MIME messages and sent as email attachments. Authentication, message construction, and transmission are clearly separated, and the implementation handles the SMTP session in a way similar to a legitimate email client.

The SMTP path is implemented in `sub_0042585D`. It performs DNS resolution with `gethostbyname` and uses socket APIs such as `socket`, `connect`, `send`, and `recv`.

![file-20260521082418961.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260521082418961.png" | relative_url }})

In the FTP path, the same set of logs can be uploaded to an FTP server. This path uses APIs such as `InternetConnectW`, `FtpSetCurrentDirectoryW`, and `FtpPutFileW`. As with the SMTP path, the actual destination and credentials depend on the configuration. The user agent passed to `InternetOpenW` is `"Ardamax Keylogger"`.

In the network-share path, the malware connects to a shared folder using `WNetAddConnection2W` and transfers logs using `MoveFileW`. This design allows collected data to be retrieved through an internal LAN share instead of the Internet.

## Log Files

The stolen data is managed as common log artifacts. The file naming patterns include HTML-based formats such as `Keys_*.html`, `Web_*.html`, and `Chat_*.html`, as well as files with custom extensions such as `.002`, `.005`, `.008`, and `.009`.

## Persistence

The malware adds a value named `"<module name> Agent"` under the `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\` registry key. The value data is set to the full path of the currently running module obtained with `GetModuleFileNameW`, enabling the malware to start automatically after a system reboot.

![file-20260521091220551.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260521091220551.png" | relative_url }})

# Analysis of DPBJ.006 (Keylogger Functionality)

![file-20260520134026638.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520134026638.png" | relative_url }})

The exported functions are shown below. Based on these exports, this DLL is likely responsible for keylogging functionality.

![file-20260520134307468.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520134307468.png" | relative_url }})

These exported functions set various hooks using `SetWindowsHookExW`.

The `SetKeyHook` function installs a `WH_KEYBOARD` hook and records the result of converting normal keyboard input to Unicode using `ToUnicodeEx`. On the other hand, the `SetMsg` function installs a `WH_GETMESSAGE` hook and obtains IME composition strings using `ImmGetCompositionStringW`.

A hook installed only by `SetHook` may not accurately capture text finalized through an IME, such as Japanese input. Therefore, this `WH_GETMESSAGE` hook appears to be intended to capture such finalized input.

SetKeyHook function: `WH_KEYBOARD` → `ToUnicodeEx` → `PostMessageW`  
SetMsgHook function: `WH_GETMESSAGE` → `ImmGetCompositionStringW` → `PostMessageW`

The `SetWndCallHook` function installs a `WH_CALLWNDPROC` hook. It compares newly created or destroyed windows against a prebuilt list of monitored windows and records the creation and destruction of those monitored windows.

The collected information is sent using a message window created by `RegisterWindowMessageW` based on the hardcoded string shown below.

![file-20260520170756755.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520170756755.png" | relative_url }})

# Analysis of DPBJ.007 (Evasion Functionality)

`DPBJ.007` is a Win32 DLL file.

![file-20260520152626511.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520152626511.png" | relative_url }})

It exports the following two functions.

![file-20260520152758029.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520152758029.png" | relative_url }})

In `DllEntryPoint`, the DLL inserts hooks for `ZwQuerySystemInformation` and `ZwEnumerateKeyValue` to implement evasion functionality.

The hook insertion code is shown below. After loading a new copy of `ntdll.dll`, the code obtains the addresses of the target APIs and overwrites the first six bytes of each function with `push <hook function address>; ret`. As a result, the hook function is executed when the `ret` instruction runs.

![file-20260520164110001.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520164110001.png" | relative_url }})

The role of the hook function for `ZwQuerySystemInformation` is to remove process information corresponding to a specified process ID from the result returned by `ZwQuerySystemInformation`. The specified process ID is the process ID of `DPBJ.exe`. This interferes with process enumeration by tools such as debuggers and Process Hacker.

![file-20260520162133657.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520162133657.png" | relative_url }})

The role of the hook function for `ZwEnumerateKeyValue` is to remove registry values with a specific name from the results of `ZwEnumerateKeyValue`. More specifically, if the registry data corresponding to the index passed as the second argument of `ZwEnumerateKeyValue` is the hidden target, the hook returns the registry data at the next index instead. In this sample, this mechanism is used to hide the registry value `"DPBJ Agent"`.

```
Actual index 0: A       shown -> index 0
Actual index 1: Hidden  hidden
Actual index 2: B       shown -> index 1
Actual index 3: C       shown -> index 2
```

![file-20260520165916398.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520165916398.png" | relative_url }})

The process ID and registry name passed to these hook functions are stored and shared in the `SHAREDAT` section.

![file-20260520170243930.png]({{ "/assets/2026-05-23-ardamax-analysis/file-20260520170243930.png" | relative_url }})

# Conclusion

This sample is an information-stealing malware associated with Ardamax. The initial executable contains multiple zlib-compressed data streams in its overlay. At runtime, it extracts these streams to create additional executable files, configuration files, and plugin DLLs.

In the initial stage, the DLL extracted from the overlay is executed, and files such as `DPBJ.exe`, `DPBJ.001`, `DPBJ.006`, `DPBJ.007`, and `key.bin` are created. Among these files, `DPBJ.exe` is the main component, `DPBJ.001` contains encrypted configuration information, `DPBJ.006` provides monitoring features such as keylogging, and `DPBJ.007` is responsible for hiding the process and registry value.

The extracted `DPBJ.exe` monitors user activity, generates logs, and exfiltrates collected information. The collected data includes keystrokes, window information, web-related information, chat-related information, clipboard contents, and screenshots. These artifacts are first saved as local log files.

The data exfiltration functionality supports three paths: SMTP, FTP, and network share. In this sample, the decrypted configuration stored in `DPBJ.001` shows that the SMTP path is mainly used. The configuration contains `smtp.mail.yahoo.com`, port 587, an email account, and a password. The FTP path uses WinINet APIs to upload log files, while the network-share path uses `WNetAddConnection2W` and `MoveFileW` to move logs to a shared folder. This structure allows the operator to choose from multiple exfiltration methods depending on the configuration.

`DPBJ.006` and `DPBJ.007` are plugin DLLs used by `DPBJ.exe`. `DPBJ.006` provides keylogging and window-monitoring functionality using Windows hooks such as `WH_KEYBOARD`, `WH_GETMESSAGE`, and `WH_CALLWNDPROC`. `DPBJ.007` implements evasion functionality by hooking NTDLL APIs. It hides the `DPBJ.exe` process from process enumeration results and hides the `DPBJ Agent` registry value from registry enumeration results.

Overall, this sample combines a compressed overlay-based unpacking mechanism, a packed main executable, configuration-driven exfiltration, input monitoring through a keylogger DLL, and artifact hiding through NTDLL API hooks. A notable characteristic of this sample is that collection, exfiltration, and evasion functionality are separated into multiple files.

As a remaining point, the detailed role of `ALK.exe` was not confirmed in this analysis. In addition, the FTP and network-share paths were confirmed at the implementation level, but in this sample the actual configuration mainly used the SMTP path.

# IOCs

## File

| Arfifact    | SHA256                                                           |
| ----------- | ---------------------------------------------------------------- |
| Initial EXE | 8c870eec48bc4ea1aca1f0c63c8a82aaadaf837f197708a7f0321238da8b6b75 |
| `@2E71.tmp` | 8aef975a94c800d0e3e4929999d05861868a7129b766315c02a48a122e3455d6 |
| `@2E81.tmp` | a67b19badad7b971cf7918716cce81fa3b63c3e7b593c583c5f99f744937f136 |
| `DPBJ.exe`  | 0fe8e3cd44a89c15dec75ff2949bac1a96e1ea7e0040f74df3230569ac9e37b0 |
| `DPBJ.001`  | b0ad9e9d3d51e8434cc466bec16e2b94fc2d03bab03b48ccf57db86ae8e2c9b6 |
| `DPBJ.006`  | 4530fcc91e4d0697a64f5e24d70e2b327f0acab1a9013102ff04236841c5a617 |
| `DPBJ.007`  | 34856528d8b7e31caa83f350bc4dbc861120dc2da822a9eb896b773bc7e1f564 |
| `key.bin`   | fc42ab050ffdfed8c8c7aac6d7e4a7cad4696218433f7ca327bcfdf9f318ac98 |
| `ALK.exe`   | 30df6c8cbd255011d80fa6e959179d47c458bc4c4d9e78c4cf571aa611cd7d24 |

## Network

| Type    | Value                  |
| ------- | ---------------------- |
| SMTP server | `smtp.mail.yahoo.com`  |
| SMTP port | 587                    |
| Mail address | `linux06400@yahoo.com` |

## Registry

| Registry Key                                         | Value                |
| ---------------------------------------------------- | -------------------- |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | `<ModuleName> Agent` |

# References

- [Dissecting Ardamax Keylogger](https://trainsec.net/library/malware-analysis/dissecting-ardamax-keylogger/)
- [Virus flow analysis: Ardamax keylogger](https://ithelp.ithome.com.tw/articles/10197301)

