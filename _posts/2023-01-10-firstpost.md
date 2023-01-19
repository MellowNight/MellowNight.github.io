---
layout: post
title: "How ForteVisor works under the hood"
date: 2023-01-19 01:01:01 -0000
categories: CATEGORY-1 CATEGORY-2
---

## Introduction

A while ago, I wrote a type-2 AMD hypervisor to dynamically analyze anti-cheats and hide internal cheats. I no longer want to treat protected software as a black box, which is why I stopped working on this project to study other topics such as deobfuscation. This is by no means a mature hypervisor that intercepts every special guest instruction. For larger projects and stable tool development, it's better to modify KVM and build your tools using KVM's interface. Although KVM has its advantages, ForteVisor will always be useful for me for building minimal, stealthy, dynamic analysis tools and writing hacks.

I will outline the implementation details of my AMD hypervisor, and explain some potential issues throughout the process. 

## Virtual machine setup

### Loading the hypervisor

To start off, I tried to load my hypervisor with KDMapper but I got some mysterious crashes. The crash dump was corrupted, so it didn't give me any helpful information. Why didn't I crash when using OSRLoader?

Apparently, The reason why it was crashing was because I was running all my initialization code and setting up guest page tables from within kdmapper's process context. After guest mode is launched, the KDmapper process exits from inside guest mode, but the host page tables are still using the old CR3 of kdmapper! I fixed this by launching my hypervisor from a system thread, so that my hypervisor host can be mapped into the page tables of the system process, which never exits.  



### Checking for AMD-V support 

Before any VM initialization, three conditions must be met:

1. AMD SVM must be supported.
2. Virtualization must be enabled in BIOS, so that VM_CR.SVMDIS can be set to 0 and VM_CR.LOCK can be locked.
3. The MSR_EFER.svme bit is set, after conditions #1 and #2 are met.

*First, we check if AMD SVM is supported*
```cpp
enum CPUID
{    
    vendor_and_max_standard_fn_number = 0x0,
    feature_identifier = 0x80000001,
};

bool IsSvmSupported()
{
	int32_t	cpu_info[4] = { 0 };

	__cpuid(cpu_info, CPUID::feature_identifier);

    /*  1. check if SVM is supported with CPUID Fn8000_0001_ECX */

	if ((cpu_info[2] & (1 << 2)) == 0)
	{
		return false;
	}

	int32_t vendor_name_result[4];

	char vendor_name[13];

	__cpuid(vendor_name_result, CPUID::vendor_and_max_standard_fn_number);
	memcpy(vendor_name, &vendor_name_result[1], sizeof(int));
	memcpy(vendor_name + 4, &vendor_name_result[3], sizeof(int));
	memcpy(vendor_name + 8, &vendor_name_result[2], sizeof(int));

	vendor_name[12] = '\0';

	DbgPrint("[SETUP] Vendor Name %s \n", vendor_name);

    /*  2. check if we are running on an AMD processor or inside a VMWare guest by 
        querying the  CPUID Fn0000_0000_E[D,C,B]X value
    */

	if (strcmp(vendor_name, "AuthenticAMD") && strcmp(vendor_name, "VmwareVmware"))
	{
		return false;
	}

	return true;
}
```

*The VM_CR.LOCK bit will be locked to 1 if virtualization is disabled in BIOS, preventing you from changing the value of VM_CR.SVMDIS. If VM_CR.LOCK is already locked and VM_CR.SVMDIS is 1, then abort initialization. Otherwise, clear VM_CR.SVMDIS and set VM_CR.LOCK*

```cpp
enum MSR : UINT64
{
    VM_CR = 0xC0010114,
};

bool IsSvmUnlocked()
{
	MsrVmcr	msr;

	msr.flags = __readmsr(MSR::VM_CR);

    /*  Check if V*/

	if (msr.svm_lock == 0)
	{
		msr.svme_disable = 0;   // 4
		msr.svm_lock = 1;       // 3
		__writemsr(MSR::VM_CR, msr.flags);
	}
	else if (msr.svme_disable == 1)
	{
		return false;
	}

	return true;
}
```
*Finally, we can enable AMD SVM extensions for this core*

```
enum MSR : UINT64
{ 
    EFER = 0xC0000080,
};

void EnableSvme()
{
	MsrEfer	msr;
	msr.flags = __readmsr(MSR::EFER);
	msr.svme = 1;
	__writemsr(MSR::EFER, msr.flags);
}
```

### Setting up the VMCB

The Virtual Machine Control Block (VMCB) contains core-specific information about the AMD virtual machine's state. It is split into two parts: the save state area and the control area.

The save state area contains most of the guest state, including general purpose registers, control registers, and segment registers. The control area mostly consists of VM configuration options for the CPU core. Host register values are simply copied to the save state area in ForteVisor.

picture here:

### MSR intercepts

ForteVisor only intercepts reads and writes to the EFER msr. The EFER.svme bit indicates that AMD SVM is enabled, so it's necessary to spoof it to zero to hide the hypervisor. 

EasyAntiCheat and Battleye write to invalid MSRs to try and trigger undefined behavior while running under the hypervisor, so I inject #GP(0) whenever the guest attempts to write to an MSR outside of the ranges specified in the manual.

*Look into the manual to see the MSR permission map format lol*
```cpp
size_t bits_per_msr = 16000 / 8000;
size_t bits_per_byte = sizeof(char) * 8;
size_t msrpm_size = PAGE_SIZE * 2;

// ...

auto section2_offset = ();

auto efer_offset = section2_offset + (bits_per_msr * (MSR::EFER - 0xC0000000));

/*	intercept EFER read and write	*/

RtlSetBits(&bitmap, efer_offset, 2);
```

*Spoofing EFER.SVME to 0*
```cpp
void HandleMsrExit(VcpuData* core_data, GuestRegisters* guest_regs)
{
    LARGE_INTEGER   msr_value{ msr_value.QuadPart = __readmsr(msr_id) };

    switch (msr_id)
    {
    case MSR::EFER:
    {
        auto efer = (MsrEfer*)&msr_value.QuadPart;

        Logger::Get()->Log("MSR::EFER caught, msr_value.QuadPart = %p \n", msr_value.QuadPart);

        efer->svme = 0;
        break;
    }
    default:
        break;
    }

    core_data->guest_vmcb.save_state_area.Rax = msr_value.LowPart;
    guest_regs->rdx = msr_value.HighPart;
}
```

*Preventing crashes from unimplemented MSR access*

```cpp
// ...
uint32_t msr_id = guest_regs->rcx & (uint32_t)0xFFFFFFFF;

if (!(
	((msr_id > 0) && (msr_id < 0x00001FFF)) || 
	((msr_id > 0xC0000000) && (msr_id < 0xC0001FFF)) || 
	(msr_id > 0xC0010000) && (msr_id < 0xC0011FFF)
	))
{
	/*  PUBG and Fortnite's unimplemented MSR checks    */

	InjectException(core_data, EXCEPTION_GP_FAULT, true, 0);
	core_data->guest_vmcb.save_state_area.Rip = core_data->guest_vmcb.control_area.NRip;

	return;
}
// ...
```


### Setting up nested paging

Nested paging/AMD RVI adds a second layer of paging that translates guest physical addresses to host physical addresses. Many cool tricks can be done using nested paging. Address translations created by ForteVisor convert guest physical addresses into identical host physical addresses.

Here's the steps to set up a nested paging directory:

1. Obtain the system physical memory ranges with MmGetPhysicalMemoryRanges. 
2. Allocate a page for npml4/nCR3
3. For each system physical page, do a page walk into the npml4, using the bits of the physical page address as indicies into the nested page tables. For each nested paging level, we check the target NPT entry's present bit. If present, we allocate a new table; otherwise, we use the existing table pointed to by the nPTE PFN.
4. At the final level, set nPTE->PFN to the physical page address itself. Boom, we've created 1:1 guest physical->host physical translation

picture:


### vmmcall interface

The guest can invoke functions in the hypervisor by executing the vmmcall instruction with specific parameters. Based on the identifier in RCX, one of the following operations are executed:

```cpp
enum VMMCALL_ID : uintptr_t
{
    disable_hv = 0x11111111,
    set_npt_hook = 0x11111112,
    remove_npt_hook = 0x11111113,
    is_hv_present = 0x11111114,
    sandbox_page = 0x11111116,
    register_instrumentation_hook = 0x11111117,
    deny_sandbox_reads = 0x11111118,
    start_branch_trace = 0x11111119,
};
```

Wrapper functions for the vmmcall interface are provided by fortevisor-api.lib. You can use it by including forte api.h and the static library in your project.

### VM launch and VM exit operation

The final step of preparing for SVM operation is executing vmload to load hidden guest state information. The vmrun instruction launches the hypervisor, stops host state execution, and loads the guest context from VMCB.

```cpp
; omitted
EnterVm:
	mov	rax, [rsp]	; put physical address of guest VMCB in rax

	vmload rax		; vmload hidden guest state

	; int 3
	
	vmrun rax		; virtualize this processor (execution will pause here)

	vmsave rax		; vmexit! save hidden state

	PUSHAQ			; save all guest general registers

	mov rcx, [rsp + 8 * 16 + 2 * 8]		; pass virtual processor data ptr in arg 1
	mov rdx, rsp					    ; pass guest registers in arg 2

	; omitted code...

	call HandleVmexit	; vmexit handler
```

Once a #VMEXIT occurs, line 


To stop the virtual machine, we do the following:

1. load guest state
2. disable IF
3. enable GIF
4. disable SVME
5. restore EFLAGS and re enable IF
6. set RBX to RIP
7. set RCX to RSP
8. return and jump to RBX

## Features

### Nested Page Table hooks

The principle of EPT/NPT stealth hooking is based off of the ability to intercept certain forms of access to pages. Page permission based hooking techniques have been used for decades, from guard page hooking to nehalem TLB-split hooking. 

Intel supports execute-only pages through extended page tables, so developers can simply create an execute-only page containing hooks, and a copy of the page, without the hooks. The VMM can then handle an access violation caused by an attempted read from the page, change the EPT mapping to the hookless page, and set the EPT mapping to read/write only. This memory read trapping mechanism effectively hides byte patches from security systems such as patchguard and Battleye. The hooked copy of this page is restored once the VMM intercepts an attempted execute on the read/write only mapping of the page.


AMD nested page tables do not support execute-only pages, so AMD system programmers need to consider two potential workarounds to achieve execute only pages:

    1. SEV-ES guests can support execute-only
    2. Page protection keys
    
Unfortunately, none of these features were supported on my AMD ryzen 2400G CPU, so I had to figure out a way to hide hooks without execute-only pages.

I created two seperate ncr3 direcories: an "hooked" ncr3 with every nPTE set to read/write only, and a "innocent" ncr3 with every nPTE allowing read/write/execute permissions. 

Let's say I wanted to place an hidden hook on a page with SetNptHook() (link to setnpthook):

1. memcpy on the page
2. 


KVA shadowing caused a problem for me, as admin programs didn't have 

binary sort and search

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
