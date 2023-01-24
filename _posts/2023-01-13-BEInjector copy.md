---
layout: post
title: "Shadow injector - hiding DLLs with nested page tables"
date: 2023-01-10 02:02:02 -0000
---

## Introduction

After months of tinkering around with AetherVisor, I desperately wanted to utilize it for something useful. I decided to write a stealthy DLL injector, powered by the capabilities of my hypervisor. After attempting several stupid ideas, I came up with a DLL injector I was finally satisfied with: one that completely hides the payload inside almost any digitally signed DLL, with the bonus of preventing dumping and debugging.

## Overview

We are going to use NPT to hide each page

## Nested Page Table hooks - review

1. __writecr3() to attach to the process cr3 saved in VMCB
2. Make a NonPagedPool copy of the target page 
3. copy the hook shellcode to copied page + hook page offset.    
4. Give rwx permissions to the nPTE of the copy page, in **"shadow"** ncr3
5. Set the nPTE permissions of the original target page to rw-only in **"primary"** (so that we can trap on executes) 
6. Create an MDL to lock the target page's virtual address to the guest physical address and, consequently, the host physical address. If the hooked page is paged out, then your NPT hook will be active on a completely random physical page!!!

## Finding the right host DLL

## aligning our DLL
