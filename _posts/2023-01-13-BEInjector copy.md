---
layout: post
title: "2D injector - hiding DLLs with nested page tables"
date: 2023-01-10 02:02:02 -0000
---

## Introduction

After months of tinkering around with AetherVisor, I desperately wanted to utilize it for something useful. I decided to write a stealthy DLL injector, powered by the capabilities of my hypervisor. After attempting several stupid ideas, I came up with a DLL injector I was finally satisfied with: one that completely hides the payload inside almost any digitally signed DLL, with the bonus of preventing dumping and debugging. 

## Overview

The principle of 2D injector is similar to that of "RWX" injectors like SWH injector https://github.com/M-r-J-o-h-n/SWH-Injector, which can be used for hiding malicious code from anti-cheats and AVs/EDRs.

Essentially, some signed DLLs, especially packed signed DLLs, might have a section marked as readable, writable, and executable that is large enough to fit a manually-mapped DLL. Code mapped inside an RWX section can bypass detections for process hollowing, because the host DLL is signed and it's difficult to check the integrity of writable sections. But, not all detection vectors will be bypassed; the RWX section can still be scanned for malicious signatures.

I wanted to hide from more than just DLL certificate checks, and I didn't want to rely on RWX dlls, which are pretty uncommon. Why not just abuse the far more common "RX" sections (i.e. the .text section) instead?

This post will go over the process of making a DLL's memory mostly invisible through nested page table manipulation. 

It's called 2D injector, because if a linear address space is one-dimensional, wouldn't two coexisting memory mappings at the same address be two dimensions? lol


**[SIMPLE DIAGRAM OF 2D INJECTOR HERE]**

## Finding the right host DLL

I will refer to the signed DLL that hosts our own manually mapped DLL as the "host dll". Our only two requirements for a host dll are that:

1. The .text and .data sections of the DLL are large enough 
\
2. The DLL is allowed to load by the the target process/game 

I plugged Overwolf's signed OWClient.dll into my injector to use as the host dll. Overwolf is an overlay software used on pretty much every game, so Battleye and EasyAntiCheat will gladly accept its DLLs. Version x.x.x has a xxxkb .text section and a xxxkb .data section.


\
\
\
\
\
\

## SetWindowsHookEx - loading the host DLL

\
\

We need to somehow remotely load the host DLL. After reversing Overwolf's DLL injection code, I found out that they use SetWindowsHookEx to call their DLL. Lets take a look at the SetWindowsHookEx() function on MSDN:

*Installs an application-defined hook procedure into a hook chain ... SetWindowsHookEx can be used to inject a DLL into another process.*

SetWindowsHookEx can be used to load the host DLL, but the documentation doesn't mention that it automatically calls the entry point. This will cause problems later down the line. 
\
\

Some DLLs will unload itself when the entry point is executed, if they aren't in the right process. You can get around this by allocating and executing a loader stub, that simply calls LoadLibrary() for the signed host DLL.  We don't need to execute the entry point, we just need the DLL to be loaded. 

[Diagram for the DLL unload problem]


## manually mapping our own invisible payload

### Nested Page Table hooks - review

We are going to 

1. __writecr3() to attach to the process cr3 saved in VMCB
2. Make a NonPagedPool copy of the target page 
3. copy the hook shellcode to copied page + hook page offset.    
4. Give rwx permissions to the nPTE of the copy page, in **"shadow"** ncr3
5. Set the nPTE permissions of the original target page to rw-only in **"primary"** (so that we can trap on executes) 
6. Create an MDL to lock the target page's virtual address to the guest physical address and, consequently, the host physical address. If the hooked page is paged out, then your NPT hook will be active on a completely random physical page!!!


### Preventing OWClient from being called twice

This is because OWClient.dll is context-aware, and tries to access Overwolf data that isn't present.


## can't call API functions


## Alternative plans 

2D injector has two issues:
- Performance: Every API call, exception, and syscall will throw #NPF and trigger an nCR3 switch. This caused a noticeable FPS drop when running internal cheats.
- Detection: The .rdata and .data sections are exposed, and can be scanned for suspicious strings. This can be partially fixed by encrypting .rdata strings, but some other suspicious data structures can't easily be encrypted.

