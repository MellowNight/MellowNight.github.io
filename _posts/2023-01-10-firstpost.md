layout: post
title: "How ForteVisor works under the hood"
date: 2023-01-10 02:02:02 -0000
categories: CATEGORY-1 CATEGORY-2

## Introduction

A while ago, I wrote a type-2 AMD hypervisor with the intention of dynamically analyzing anti-cheats and hiding internal cheats. I no longer want to treat protected software as a black box, which is why I stopped working on this project to study other topics such as deobfuscation. This is by no means a mature hypervisor that intercepts every guest hardware call. For larger projects and stable tool development, it's better to modify KVM and build your tools using KVM's interface. Although KVM has its advantages, ForteVisor will always be useful for me for building minimal, stealthy, dynamic analysis tools and writing hacks.

I will outline the implementation details of my AMD hypervisor, and explain some potential issues throughout the process. 

## Virtual machine setup


### Loading the HV driver

To start off, I tried to load my hypervisor with KDMapper but I got some mysterious crashes. The crash dump was corrupted, so it didn't give me any helpful information. Why didn't I crash when using OSRLoader?

Apparently, The reason why it was crashing was because I was running all my initialization code and setting up guest page tables from inside kdmapper's process context. After guest mode is launched, the KDmapper process exits from inside guest mode, but the host page tables are still using the old CR3 of kdmapper! I fixed this by launching my hypervisor from a system thread, so that my hypervisor host can be safely mapped into the page tables of the system process, which never exits.  

### Checking for AMD-V support 

Before any VM initialization, three conditions must be met:

1. AMD SVM must be supported.
2. Virtualization must be enabled in BIOS.
3. The SR_EFER.svme bit is set, after conditions #1 and #2 are met.


```

int32_t	cpu_info[4] = { 0 };

__cpuid(cpu_info, CPUID::processor_feature_identifier);

if ((cpu_info[2] & (1 << 1)) == 0)
{
    return false;
}
```

### Setting up the VMCB

Most of the registers in the guest VMCB are initialized with host values. The control area is loaded with host cr3. The save state area is loaded with the host RFLAGS, segment descriptors, and 



### Setting up MSR intercepts

I configured the MSR permissions map to only exit on reads and writes to the EFER msr. SVM status can be hidden by setting the EFER.svme bit in rax to 0, after handling the read from the EFER MSR. EasyAntiCheat and Battleye write to invalid MSRs to try and trigger undefined behavior while running under the hypervisor, so I inject #GP(0) whenever an MSR outside of the MSR ranges specified in the manual is written to. 

```
```

### Setting up nested paging

Nested paging/AMD RVI is a feature that adds a second layer of paging that translates guest physical addresses to host physical addresses. Many cool tricks can be done using nested paging.

I'm identity mapping guest physical addresses are 1:1 mapped to host physical addresses

 After obtaining the system physical memory ranges with MmGetPhysicalMemoryRanges, the bits of each physical page is used as indices into the nested page tables. If a nested page table entry corresponding to the guest physical address does not exist, a new table is allocated, and the guest physical address is

### Processor consistency checks

According to the AMD manual, 

### vmmcall interface

The guest can invoke functionality in the hypervisor by executing the vmmcall instruction with specific parameters. Based on the identifier in RCX, one of the following operations is invoked:

```
```

I created the fortevisor-api.lib library to provide wrapper functions for communicating to the hypervisor via vmmcall.

```



```

## VM launch and VM exit operation

## Features

### Nested Page Table hooks

The principle of EPT/NPT stealth hooking is based off of the ability to intercept certain forms of access to pages. Page permission based hooking techniques have been used for decades, from guard page hooking to nehalem TLB-split hooking. 

Intel supports execute-only pages through extended page tables, so developers can simply create an execute-only page containing hooks, and a copy of the page, without the hooks. The VMM can then handle an access violation caused by an attempted read from the page, change the EPT mapping to the hookless page, and set the EPT mapping to read/write only. This memory read trapping mechanism effectively hides byte patches from security systems such as patchguard and Battleye. The hooked copy of this page is restored once the VMM intercepts an attempted execute on the read/write only mapping of the page.


AMD nested page tables do not support execute-only pages, so AMD system programmers need to consider two potential workarounds to achieve execute only pages:

    1. SEV-ES guests can support eexecute-only
    2. Page protection keys
    
Unfortunately, none of these features were supported on my AMD ryzen 2400G CPU, so I had to figure out a way to hide hooks without execute-only pages. I created two completely seperate ncr3 direcories: one with every single trapping on execute 



### Sandboxing 



### Read Write logging

### Branch Tracing

My implementation of branch tracing utilizes LBR (Last Branch Record) to record LastBranchToIP and LastBranchFromIP, and BTF (Branch Trap Flag) to throw #DB to the hypervisor for every branch executed. Using the LBR stack without BTF would greatly reduce overhead, but AMD doesn't provide any mechanism to signal when the LBR stack is full :((((. I also considered 

When I wanted to test extended debug features in my hypervisor, I was misled by some inconsistencies that VMware and Windows had with the AMD system programming manual. 

First of all, I tried testing within VMware, but nothing happened when I enabled BTF and LBR. DebugCtl features were all supported according to the results of cpuid, so I was really confused. After reviewing the documentation for DebugCtl in the AMD manual several times, I just checked if the DebugCtl.LBR bit was still set after I set it, but it wasn't. Apparently, VMware was forcing these debugctl features to be disabled, which meant that I had to do some testing outside of VMware. 

Secondly, Windows manages debugctl features in a special way. According to the AMD manual, LBR tracing and BTF (branch single step) operation are controlled by bits in the DebugCtl MSR. I set the bits accordingly and the bits stayed that way, but #DB was being thrown, even though cpuid indicated that both were supported . I spent hours and hours figuring out my issue, until I realized that bit 8 and 9 in DR7  control the LBR tracing and BTF bits in windows.

### Process-specific syscall hooks

in progress...

## Future plans

I have more interesting projects to work on, but if I ever decide to extend my hypervisor, I would write a x64dbg plugin to interface with it.
