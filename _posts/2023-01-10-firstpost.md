layout: post
title: "How ForteVisor works under the hood"
date: 2023-01-10 02:02:02 -0000
categories: CATEGORY-1 CATEGORY-2

## Introduction

A while ago, I wrote a type-2 AMD hypervisor with the intention of being able to dynamically analyze anti-cheats and hide the memory of internal cheats. I no longer want to treat protected software as a black box, which is why I stopped working on this project so that I can study more about devirtualization. This is by no means a mature hypervisor that supports interfacing with every guest hardware call. For larger projects and stable tool development, it's better to modify KVM and build your tools using KVM's interface. Although KVM has its advantages, ForteVisor will always be useful for me for building minimal, stealthy, dynamic analysis tools and writing hacks.

I will outline the implementation details of my AMD hypervisor, and explain some potential issues throughout the process. 

## VM setup

### Loading the HV driver

To start off, I decided to load my hypervisor with KDMapper but I got some mysterious crashes. The crash dump was corrupted, and it didn't give me any helpful information. Why didn't I crash when using OSRLoader?

Apparently, The reason why it was crashing was because I was running all my initialization code and setting up guest page tables from inside kdmapper's process context. After guest mode is launched, the KDmapper process exits from inside guest mode, but the host page tables are still using the old CR3 of kdmapper! By launching my hypervisor from a system thread, my host page tables will be based off of the SYSTEM process, which never exits. 

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



### Setting up the MSR permissions map


### Setting up nested paging

Nested paging/AMD RVI is a feature that adds a second layer of paging that translates guest physical addresses to host physical addresses. So many cool tricks can 

### vmmcall interface

### Putting it all together


## VM launch and VM exit operation

## Features

### Nested Page Table hooks

Based on nested page table hooks, I 

### Sandboxing 

### Read Write logging

### Branch Tracing

My implementation of branch tracing utilizes LBR (Last Branch Record) to record LastBranchToIP and LastBranchFromIP, and BTF (Branch Trap Flag) to throw #DB to the hypervisor for every branch executed. Using the LBR stack without BTF would greatly reduce overhead, but AMD doesn't provide any mechanism to signal when the LBR stack is full :((((. I also considered 

When I wanted to test extended debug features in my hypervisor, I was misled by some inconsistencies that VMware and Windows had with the AMD system programming manual. 

First of all, I tried testing within VMware, but nothing happened when I enabled BTF and LBR. DebugCtl features were all supported according to cpuid, so I was so confused about what I was missing. After reviewing the documentation for DebugCtl in the AMD manual several times, I just checked if the DebugCtl.LBR bit was still set after I set it, but it wasn't. Apparently, VMware was forcing these debugctl features to be disabled, which meant that I had to do some testing outside of VMware. 

Secondly, Windows manages debugctl features in a special way. According to the AMD manual, LBR tracing and BTF (branch single step) operation are controlled by bits in the DebugCtl MSR. I set the bits accordingly and the bits stayed that way, but #DB was being thrown, even though cpuid indicated that both were supported . I spent hours and hours figuring out my issue, until I realized that bit 8 and 9 in DR7  control the LBR tracing and BTF bits in windows.

### Process-specific syscall hooks

in progress...

## Future plans

I have more interesting projects to work on, but if I ever decide to extend my hypervisor, I would write a x64dbg plugin to interface with it.