---
layout: post
title: "2D injector - hiding DLLs with nested page tables"
date: 2023-01-10 02:02:02 -0000
author: MellowNight
---

<br>

- [Introduction](#introduction)
- [Overview](#overview)
  * [Finding the right host DLL](#finding-the-right-host-dll)
  * [SetWindowsHookEx - loading the host DLL](#setwindowshookex---loading-the-host-dll)
  * [Manually mapping our payload DLL](#manually-mapping-our-payload-dll)
    + [Nested Page Table hooks - review](#nested-page-table-hooks---review)
    + [Calling the entry point](#calling-the-entry-point)
  * [Why I'm unable to hide the entire DLL](#why-i-m-unable-to-hide-the-entire-dll)
- [Limitations & Alternative ideas](#limitations---alternative-ideas)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

<br>

github repo can be found here: [AetherVisor](https://github.com/MellowNight/ForteVisor)

<br>

## Introduction

&emsp;&emsp;After months of tinkering around with AetherVisor, I wanted to utilize it for something useful. I decided to write a stealthy DLL injector, powered by the features of AetherVisor. After attempting several stupid ideas, I came up with a DLL injector I was finally satisfied with: one that hides the payload inside almost any digitally signed DLL, with the bonus of preventing dumping and debugging. 

<br>

## Overview

&emsp;&emsp;The principle of 2D injector is similar to that of "RWX" injectors like [SWH injector](https://github.com/M-r-J-o-h-n/SWH-Injector), which can be used for hiding malicious code from anti-cheats and antivirus/EDR solutions.

<br>

&emsp;&emsp;Essentially, some signed DLLs, especially packed signed DLLs, might have a section marked as readable, writable, and executable that is large enough to fit a manually-mapped DLL. Code mapped inside an RWX section can bypass detections for process hollowing, because the host DLL is signed and it's difficult to check the integrity of writable sections. But, not all detection vectors will be bypassed; the RWX section can still be scanned for malicious signatures.

<br>

I wanted to hide from more than just DLL certificate checks, and I didn't want to rely on RWX dlls, which are pretty uncommon. Why not just abuse the far more common "RX" sections (i.e. the .text section) instead?

<br>

This post will go over the process of injecting a DLL and making its memory mostly invisible through nested page table (NPT) manipulation.

<br>

[INSERT VIDEO HERE]

<br>

*It's called 2D injector, because if a linear address space is one-dimensional, wouldn't two coexisting memory mappings at the same address be two dimensions? lol*


<br>

### Finding the right host DLL

&emsp;&emsp;I will refer to the signed DLL that hosts our own manually mapped DLL as the **"host dll"**. Our only two requirements for a host dll are that:

<br>

1. The .text and .data sections of the DLL are large enough 
2. The DLL is allowed to load by the the target process/game 

<br>

&emsp;&emsp;I plugged Overwolf's signed OWClient.dll into my injector to use as a host dll. Overwolf is an overlay software used on pretty much every game, so Battleye and EasyAntiCheat will gladly accept its DLLs. Version x.x.x has a xxxkb .text section and a xxxkb .data section.

<br>

[INSERT OWCLIENT CFF PICTURE HERE]

<br>

### SetWindowsHookEx - loading the host DLL

&emsp;&emsp;We need to somehow remotely load the host DLL. After reversing Overwolf's DLL injection code, I found out that they use SetWindowsHookEx to inject their DLL. Lets take a look at the SetWindowsHookEx() function on MSDN:

<br>

*"[SetWindowsHookEx] Installs an application-defined hook procedure into a hook chain. You would install a hook procedure to monitor the system for certain types of events. These events are associated either with a specific thread or with all threads in the same desktop as the calling thread ... SetWindowsHookEx can be used to inject a DLL into another process."*

<br>

```
/*
  [in] idHook - The type of hook procedure to be installed.
  [in] lpfn - A pointer to the hook procedure.
  [in] hmod - A handle to the DLL containing the hook procedure pointed to by the lpfn parameter. 
  [in] dwThreadId - The identifier of the thread with which the hook procedure is to be associated. 
*/

HHOOK SetWindowsHookExA(
  [in] int       idHook,
  [in] HOOKPROC  lpfn,
  [in] HINSTANCE hmod,
  [in] DWORD     dwThreadId
);
```

<br>

&emsp;&emsp;SetWindowsHookEx loads the DLL into the process that owns the thread with the ID dwThreadId, and then calls the hook routine specified by lpfn. The documentation doesn't mention that it also automatically calls the entry point. Calling the entry point has potential issues that we'll need to avoid later down the line. 

<br>

The first problem is that some DLLs will unload themselves when the entry point is executed, if they aren't in the right process. You can get around this by allocating and executing a loader stub, that simply calls LoadLibrary() for the signed host DLL. We don't need to execute the entry point, we just need the DLL to be loaded. 

<br> 

[Diagram for the DLL unload problem]

<br>

### Manually mapping our payload DLL

&emsp;&emsp;After loading the host DLL, we prepare our payload DLL for manual mapping like any other injector. This includes remapping sections to their relative virtual addresses, resolving relocations, and resolving imports. In this next section, we'll go over how our own payload DLL is mapped to the target process.

<br>

#### Nested Page Table hooks - review

&emsp;&emsp;AetherVisor's NPT hook feature will create a shadow copy of a page that is only visible when RIP enters the page. My implementation of NPT hooking is described in more detail in my [AetherVisor writeup](https://mellownight.github.io/2023/01/19/AetherVisor.html)

<br>

The objective here is to map the entire payload inside of the NPT hook shadow pages. This way, our DLL memory will only be visible while it is executing.

<br>

*The concept is pretty simple, here's pseudocode for mapping our entire DLL payload inside the shadow copy of a legit DLL:*
<br>
```
for (offset = cheat_mapped; offset < cheat_mapped + cheat_size; offset += PAGE_SIZE)
{
    Driver::SetNptHook(target_processid, PAGE_SIZE, host_dll_base + (offset - cheat_mapped), offset);
}	
```
<br>
&emsp;&emsp;The SetNptHook function is used to install hidden NPT hooks. It only works within the caller's process, so I wrote a kernel driver to attach to the target process using KeStackAttachProcess and hide the payload DLL pages. The 4KB payload pages are passed through the "hook_shellcode" argument, and the host DLL pages through "hook_target". We are replacing many pages at the beginning of the host DLL.

<br>

*NOTE: spamming #VMEXIT in a loop like this could lead to a CLOCK_WATCHDOG_TIMEOUT, if the vmexit handler for SetNptHook() isn't well optimized enough.*

<br>

Here's how Driver::SetNptHook maps in a page from our DLL:

<br>

1. __writecr3() to attach to the process context saved in VMCB
2. Create a non-paged pool shadow copy of the host DLL 4KB page
3. Copy the 4KB page from our own DLL to this **shadow** copy.    
4. Update the target page nPTE's PFN in the **shadow** nCR3 to our **shadow** page 
5. Set the permissions of the **shadow** nCR3 nPTE to RWX
6. Set the permissions of the **primary** nCR3 nPTE (which points to the original host DLL page) to rw-only
7. Create an MDL to lock the hooked page's virtual address to the guest and host physical addresses.

<br>

[INSERT INJECTOR DIAGRAM HERE]

<br>

&emsp;&emsp;Upon executing the RW-only regions in the host DLL, #NPF will be thrown, causing the hypervisor to switch to the shadow nCR3 and revealing the payload DLL. When RIP leaves the memory range of our payload DLL, another #NPF is thrown, causing the hypervisor to switch back to the primary nCR3, hiding the payload.

<br>

#### Calling the entry point

&emsp;&emsp;We are going to use SetWindowsHookEx again to invoke the entry point for our hidden DLL. [Earlier](#setwindowshookex---loading-the-host-dll), I mentioned a potential problem caused by SetWindowsHookEx automatically calling the entry point of the host DLL (OWClient.dll).

<br>

Another problem is that OWClient.dll's entry point crashes, because it tries to access Overwolf data that isn't present.

<br>

### Why I'm unable to hide the entire DLL

&emsp;&emsp;After hiding the entire DLL, calling some API functions causes access violations. Why is that? Let's investigate the crash:

<br>

[CHEAT ENGINE SCREENSHOT HERE]

<br>

Here, we can see that LoadLibrary() crashes when It tries to access a string inside our DLL. This is probably because the .rdata and .data sections of our DLL is completely hidden, so our strings and other variables are not accessible to DLL dependencies. This means that I'm unable to hide the entire DLL; .rdata and .data must be visible for some other DLLs, such as kernel32.dll and ntdll.dll. We can't hide .rdata, but we also can't simply write .rdata to read-only sections of the OWClient; that would violate integrity checks. 

<br>

The only solution is to align the .rdata of our payload DLL with the .data section of OWClient, and map our payload to **(OWClient.dll + overwolf_data_section_rva) - payload_rdata_section_rva**. Unfortunately, now the only sections that can be hidden are PE headers, .text, and .idata, which come before .rdata.

<br>

[RDATA ALIGNMENT DIAGRAM HERE:]


<br>

## Limitations & Alternative ideas

2D injector has two issues:

<br>

- Performance: Every API call, exception, and syscall triggers an #NPF vmexit. Not only that, but vmexit is also triggered every time a hidden hook is executed. The frequent vmexits caused a noticeable FPS drop with some of my internal cheats. 
- Detection: The .rdata and .data sections are exposed, and can be scanned for suspicious strings. This can be partially fixed by encrypting .rdata strings, but some other suspicious data structures can't easily be encrypted.

