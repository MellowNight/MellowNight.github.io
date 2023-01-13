layout: post
title: "How ForteVisor works under the hood"
date: 2023-01-10 02:02:02 -0000
categories: CATEGORY-1 CATEGORY-2

## Introduction

A while ago, I wrote a type-2 AMD hypervisor with the intention of being able to dynamically analyze anti-cheats and hide the memory of internal cheats. I no longer want to treat the anti-cheat as a black box, which is why I deferred working on this project so that I can study more about devirtualization. This is by no means a very mature hypervisor with an interface to handle every guest hardware call. For larger projects and stable tool development, it's better to modify KVM and build your tools using KVM's interface. Although KVM has its advantages, ForteVisor will always be useful for me for building minimal, stealthy, dynamic analysis tools and writing hacks.

I will outline the implementation details of my AMD hypervisor, and explain some potential issues with its functionality. 

## VM setup

### Checking for AMD-V support 

kdmapper modifications
Before any initialization, I check if the model specific registers for 

### Setting up the VMCB

### Setting up the MSR permissions map


### Setting up nested paging

### Putting it all together



## VM launch and VM exit operation

## Features

### Nested Page Table hooks

Based on nested page table hooks, I 

### Sandboxing 

### Read Write logging

### Branch Tracing

My implementation of branch tracing utilizes LBR (Last Branch Record) to record branch information and BTF (Branch Trap Flag) to report branches executed by the thread to the hypervisor. I wanted to use the LBR stack alone, but AMD doesn't provide a LBR stack vmexit to signal to me when the LBR stack is full  :((((. I also considered 

When I wanted to test extended debug features in my hypervisor, I was misled by some inconsistencies that VMware and Windows had with the AMD system programming manual. 

First of all, I tried testing within VMware, but for some reason nothing happened when I enabled BTF and LBR. The support for DebugCtl features were all enabled, so I just sat there thinking about what I might've been missing. After reviewing everything related to DebugCtl in the AMD manual several times, I just checked if the DebugCtl.LBR bit was still set after I set it, but it wasn't. Apparently, VMware was forcing these debugctl features to be disabled, which meant that I had to do some testing outside of VMware. 

Secondly, Windows manages debugctl features in a special way. According to the AMD manual, LBR tracing and BTF (branch single step) operation are controlled by bits in the DebugCtl MSR. I set the bits accordingly and the bits stayed that way, but #DB was being thrown, even though cpuid indicated that both were supported . I spent hours and hours figuring out my issue, until I realized that bit 8 and 9 in DR7  control the LBR tracing and BTF bits in windows.

### Process-specific syscall hooks

in progress...