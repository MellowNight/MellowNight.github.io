---
layout: post
title: "How AetherVisor works under the hood"
date: 2023-01-19 01:01:01 -0000
author: MellowNight
---

<br>

## Introduction

&emsp;&emsp;A while ago, I wrote AetherVisor: a stealthy dynamic analysis and memory hacking framework, based on a type-2 AMD hypervisor. I no longer want to treat protected software as a black box, so I paused this project to study other topics such as x86 deobfuscation. AetherVisor is a minimal hypervisor, so it may be unstable, and many special instruction intercepts aren't supported. For more robust and stable tool development, it's better to use more established options like KVM. Although KVM has its advantages, AetherVisor remains a valuable tool for building minimal, stealthy, debugger tools and writing hacks.
<br>
<br> 

This is a general overview of AetherVisor's implementation, with insight into some potential issues.

<br> 

## Virtual machine setup

This first section will go over the initialization and launch process for AetherVisor.

<br> 

### Checking for AMD-V support 

Before any VM initialization, three conditions must be met:
<br> 
1. AMD SVM must be supported.
2. Virtualization must be enabled in BIOS, so that VM_CR.SVMDIS can be set to 0 and VM_CR.LOCK can be locked.
3. The MSR_EFER.svme bit is set, after conditions #1 and #2 are met.

<br> 

*First, check if AMD SVM is supported:*

<br> 
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

	// 1. check if SVM is supported with CPUID Fn8000_0001_ECX

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

	// 2. check if we are running on an AMD processor or inside a VMWare guest by 
	// querying the  CPUID Fn0000_0000_E[D,C,B]X value

	if (strcmp(vendor_name, "AuthenticAMD") && strcmp(vendor_name, "VmwareVmware"))
	{
		return false;
	}

	return true;
}
```
<br> 
<br> 

*The VM_CR.LOCK bit will be locked to 1 if SVM is disabled in BIOS, preventing you from changing the value of VM_CR.SVMDIS. If VM_CR.LOCK is already locked and VM_CR.SVMDIS is 1, then abort initialization. Otherwise, clear VM_CR.SVMDIS and set VM_CR.LOCK.*

<br> 

```cpp
enum MSR : UINT64
{
    VM_CR = 0xC0010114,
};

bool IsSvmUnlocked()
{
	MsrVmcr	msr;

	msr.flags = __readmsr(MSR::VM_CR);

	/*  Check if SVM is locked	*/

	if (msr.svm_lock == 0)		// bit 3
	{
		msr.svme_disable = 0;   // bit 4
		msr.svm_lock = 1;       
		__writemsr(MSR::VM_CR, msr.flags);
	}
	else if (msr.svme_disable == 1)
	{
		return false;
	}

	return true;
}
```

<br>
<br>
*Finally, we can enable AMD SVM for this core:*

<br>

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
<br>

### Setting up the VMCB


&emsp;&emsp;The Virtual Machine Control Block (VMCB) contains core-specific information about the AMD virtual machine's state. It is split into two parts: the save state area and the control area.

<br>

&emsp;&emsp;The save state area contains most of the guest state, including general purpose registers, control registers, and segment registers. The control area mostly consists of VM configuration options for the CPU core. Host register values are simply copied to the save state area in AetherVisor.

<br>

*The VMCB:*

<br>

![alt text](https://raw.githubusercontent.com/MellowNight/MellowNight.github.io/main/assets/img/VMCB.png "Logo Title Text 1")

<br> 

### MSR intercepts

&emsp;&emsp;AetherVisor only intercepts reads and writes to the EFER msr. The EFER.svme bit indicates that AMD SVM is enabled, so it's necessary to spoof it to zero to hide the hypervisor. 

<br>

*Look into the manual to see the MSR permission map format lol*

<br>

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

<br>
<br>
*Spoofing EFER.SVME to 0*

<br>

```cpp
void HandleMsrExit(VcpuData* core_data, GuestRegisters* guest_regs)
{
    LARGE_INTEGER   msr_value{ msr_value.QuadPart = __readmsr(msr_id) };

    switch (msr_id)
    {
		case MSR::EFER:
		{
			auto efer = (MsrEfer*)&msr_value.QuadPart;
			efer->svme = 0;
			break;
		}
    }

    core_data->guest_vmcb.save_state_area.Rax = msr_value.LowPart;
    guest_regs->rdx = msr_value.HighPart;
}
```

<br> 

&emsp;&emsp;EasyAntiCheat and Battleye write to unimplemented MSRs to try and trigger undefined behavior while running under the hypervisor, so I inject #GP(0) when the guest writes to an MSR outside the manual's specified ranges.

<br>
 
*Preventing crashes from unimplemented MSR access*

<br>

```cpp
// ...

uint32_t msr_id = guest_regs->rcx & (uint32_t)0xFFFFFFFF;

if (!(
	((msr_id > 0) && (msr_id < 0x00001FFF)) || 
	((msr_id > 0xC0000000) && (msr_id < 0xC0001FFF)) || 
	(msr_id > 0xC0010000) && (msr_id < 0xC0011FFF)
	))
{
	/*  Battleye/EAC/PUBG unimplemented MSR checks    */

	InjectException(core_data, EXCEPTION_GP_FAULT, true, 0);
	return;
}

// ...
```

<br>

### Setting up nested paging

&emsp;&emsp;Nested paging/AMD RVI adds a second layer of page tables that translates gPA (guest physical address) to hPA (host physical address). gPA are identity mapped to hPA with AetherVisor's nested page table setup. A lot of magic can be done by manipulating NPT entries, such as hiding memory, hiding hooks, isolating memory spaces, etc. Think outside of the box :) 

<br>

#### Here's how to set up an nested page directory with identity mapping:

1. Obtain physical memory ranges using MmGetPhysicalMemoryRanges. 
2. Allocate a page for npml4/nCR3
3. Do a page walk into the nCR3 directory using each physical page address. For each nested page level, we check the indexed NPT entry's present bit. If present == 0, we use the existing table pointed to by NPT entry's PFN; otherwise, we allocate a new table for the PFN
4. At the last level, point nPTE->PFN to the physical page address itself.

<br>

Boom, we've created a 1:1 gPA->hPA mapping for a page.

<br>

*This is basically the same as normal virtual->physical paging lol*

<br>

![alt text](https://raw.githubusercontent.com/MellowNight/MellowNight.github.io/main/assets/img/NestedPagingSetup.png "Logo Title Text 1")

<br>

### vmmcall interface

The guest can interface with the hypervisor by executing the vmmcall instruction with specific parameters. Based on the code passed in RCX, one of the following operations are executed:

<br>

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

<br>

Wrapper functions for the vmmcall interface are provided by aethervisor-api.lib. You can use it by including aether_api.h and the static library in your project.

<br>

### VM launch and VM exit operation

The final step of preparing for SVM operation is executing vmload to load hidden guest state information. The vmrun instruction launches the hypervisor, stops host state execution, and loads the guest context from VMCB.

<br>

```cpp
; omitted
EnterVm:
	mov rax, [rsp]	; put physical address of guest VMCB in rax

	vmload rax		; vmload hidden guest state

	; int 3

	vmrun rax		; virtualize this processor (execution will pause here)

	vmsave rax		; vmexit! save hidden state

	PUSHAQ			; save all guest general registers

	mov rcx, [rsp + 8 * 16 + 2 * 8]	; pass virtual processor data ptr in arg 1
	mov rdx, rsp					; pass guest registers in arg 2

	; omitted code...

	call HandleVmexit	; vmexit handler
```

<br>

Once a #VMEXIT occurs, execution resumes and line 11 is reached.

<br>

### Stopping the hypervisor

To completely stop the hypervisor, we vmexit out of guest state, disable SVM, load the guest state registers, and resume execution where the guest exited. 

There are multiple steps involved. In the C++ vmexit handler, we do the following:

<br>

In HandleVmexit():
```
if (end_hypervisor)
{	
	// 1. Load guest CR3 context
	__writecr3(vcpu_data->guest_vmcb.save_state_area.Cr3.Flags);

	// 2. Load guest hidden context
	__svm_vmload(vcpu_data->guest_vmcb_physicaladdr);
	
	// 3. Enable global interrupt flag
	__svm_stgi()
	
	// 4. Disable interrupt flag in EFLAGS (to safely disable SVM)
	_disable()

	MsrEfer msr;

	msr.flags = __readmsr(MSR::EFER);
	msr.svme = 0;

	// 5. disable SVM
	__writemsr(MSR::EFER, msr.flags);

	// 6. load the guest value of EFLAGS
	__writeeflags(vcpu_data->guest_vmcb.save_state_area.Rflags.Flags);	

	// 7. restore these values later
	guest_ctx->rcx = vcpu_data->guest_vmcb.save_state_area.Rsp;
	guest_ctx->rbx = vcpu_data->guest_vmcb.control_area.NRip;

	Logger::Get()->Log("ending hypervisor... \n");
}

return end_hypervisor;

// ...
```

<br>

After disabling virtualization, there is no more "guest" state; there is only the "host" processor state. We will resume execution from where the guest left off:

<br>

```
	call HandleVmexit	; the C++ vmexit handler

	;  omitted asm...

	test al, al	; if return 1, then end VM

	POPAQ	; 8. load the guest's general purpose register context

	; ...

EndVm:
	; in HandleVmexit, rcx is set to guest stack pointer, and rbx is set to guest RIP
	; but guest state is already ended so we continue execution as host

	mov rsp, rcx	; 9. load guest stack

	jmp rbx		; 10. resume execution from where the guest exited

LaunchVm endp
```

<br>

## Loading the hypervisor

&emsp;&emsp;Most of the time, I just used OSRLoader to test my hypervisor, which worked flawlessly. However, when I attempted to launch the hypervisor with KDMapper, I got the following VMWare error:

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/MellowNight/MellowNight.github.io/main/assets/img/kdmapperfault1.PNG">
</p>

<br>

&emsp;&emsp;Unfortunately, there was no crash dump, so I was unable to gather any useful information. I was confused as to why there were no similar issues with OSRLoader. There were two things I was certain of: First, the hypervisor launched successfully on all cores, and second, the crash occurred some time after I exited my driver. To learn more about this KDMapper issue, I wanted to see what happened when I triggered a vmexit before exiting DriverEntry, and what happened when vmexited outside of AetherVisor's entry point. I placed a breakpoint after vmrun, to catch vmexits:

<br>

*breakpoint after vmrun, to catch #VMEXIT:*

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/MellowNight/MellowNight.github.io/main/assets/img/kdmapperfault2.PNG">
</p>

<br>

*vmmcall #VMEXIT test in a seperate driver, ran after AetherVisor's entry point returns:*

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/MellowNight/MellowNight.github.io/main/assets/img/kdmapperfault3.PNG">
</p>

<br>

&emsp;&emsp;I vmmcall'ed the hyperivsor before returning from DriverEntry, and then I executed vmmcall from a 2nd driver. The breakpoint I placed right after vmrun should've been hit twice, but only one breakpoint was hit before the crash.

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/MellowNight/MellowNight.github.io/main/assets/img/kdmapperfault4.jpg">
</p>

<br>

&emsp;&emsp;This must mean that the vmexit handler is somehow fked up after DriverEntry returns! If the breakpoint on vmexit is not being reached, and the exception handlers crash without double fault or bluescreen, I can assume that either the segments are messed up, or no code is mapped to the CR3 context. 

<br>

&emsp;&emsp;I came to the conclusion that I received the crash because AetherVisor was initialized from within kdmapper's process context, thus KDMapper's CR3 would have been saved in guest VMCB. After guest mode is launched, the KDmapper process exits inside guest mode, but the host page tables (used for vmexit handlers) are still using the KDMapper's CR3! I fixed this by launching my hypervisor from a system thread, in the context of system process, which never exits.  

<br>

## Features

In this second section, I will explain the implementation details of features provided by AetherVisor.

<br>

### Nested Page Table hooks


&emsp;&emsp;EPT/NPT hooking is a technique to hide inline hooks, by intercepting and redirecting memory reads to a different page. 

<br>

&emsp;&emsp;Intel supports execute-only pages through extended page tables, so developers can simply create an execute-only page containing hooks, and a copy of the page, without the hooks. An Intel HV can handle EPT faults caused by attempted reads from the page, and redirect the read to the copy page. The hooked page is restored on EPT faults thrown by instruction fetches from the page. 
<br>

[Intel EPT hook diagram here]


<br>

&emsp;&emsp;AMD nested page tables do not support the execute-only permission, so AMD system programmers might need to trap every execute access to the hook page, which causes overhead. Two workarounds can be considered to achieve execute-only pages on AMD:

<br>

**SEV-SNP (secure nested paging):** pages in the guest can be restricted to execute-only with VMPL permission masks in the RMP (reverse map table). These RMP permission checks are only in effect when SEV-SNP is enabled. See AMD system programming manual sections 15.36.3 to 15.36.5.  
      
**Memory Protection Keys:** execute-only memory can be achieved with with MPK by disabling read access
through the PKRU register and allowing execution through the page table. Memory protection keys control read and write access to pages, but ignore instruction fetches. See AMD system programming manual section 5.6.7.
    
<br>

Unfortunately, none of these features were supported on my AMD ryzen 2400G CPU, so I needed to somehow hide hooks by trapping on execute.

<br>

&emsp;&emsp;To start off, I set up two ncr3 direcories: a **"shadow"** ncr3 with every page set to read/write only, and a **"primary"** ncr3 with every page allowing read/write/execute permissions. By default, the **"primary"** nCR3 is used. Whenever we execute the hooked page, #NPF is thrown and we enter into the **"shadow"** ncr3. The processor switches back to **"primary"** ncr3 whenever RIP goes outside of the hooked page.

<br>

The following steps describe how the NPT hook is set:

<br>

1. __writecr3() to attach to the process context saved in VMCB
2. Make a NonPagedPool **shadow** copy of the target page 
3. Copy the hook shellcode to copy page + hook page offset.    
4. Give rwx permissions to the nPTE of the copy page, in **"shadow"** ncr3
5. Set the nPTE permissions of the original target page to rw-only in **"primary"** (so that we can trap on executes) 
6. Create an MDL to lock the target page's virtual address to the guest physical address and, consequently, the host physical address. *If the hooked page is paged out, then your NPT hook will redirect execution on some unknown memory page!!!*

<br>

*This diagram for SetNptHook()[an NPT hook(link to setnpthook)] is a lot easier to understand:*

<br>

![alt text](https://raw.githubusercontent.com/MellowNight/MellowNight.github.io/main/assets/img/NestedPagingSetup.png "Logo Title Text 1")


<br>

&emsp;&emsp;One problem was caused by Windows' KVA shadowing feature, which created two CR3 contexts for each process: Usermode dirbase and kernel dirbase. Invoking SetNptHook() from usermode caused the 1st step listed above to crash, because the VMCB would store the usermode dirbase, where AetherVisor's code wasn't even mapped. Any process interfacing with AetherVisor must run as administrator to prevent this crash!

<br>

After setting the NPT hook, the hooked page will throw #NPF vmexit on instruction fetch. This is how the #NPF is handled:


**[AMD NPT hook diagram here, WITH STEPS!!!]**


<br>

**When two adjacent pages have conflicting execute permissions, an #NPF might occur from an instruction split across the page boundary. This will cause an infinite #NPF loop, so you must figure out how to execute the entire instruction safely. I spent 24+ days debugging this!!*


### Sandboxing 


&emsp;&emsp;We just saw how we can mess with EPT/NPT entries to manipulate data exposed to the guest; you can also isolate memory regions and control read, write, and execute access coming from the region. This serves as the basis for some current EDR, software containerization, or reverse engineering/dynamic analysis solutions. KVM's EPT/NPT capability is used by Intel Kata and Docker Desktop to isolate containers. The concept behind AetherVisor's NPT sandbox is similar to Bromium's LAVA tool. 


#### intercepting out-of-module execution


AetherVisor's sandboxing feature isolates a memory region by disabling execute for its pages in the **"Primary"** nCR3 context. The sandboxed pages behave the same way as NPT hooked pages, but a third nCR3, named **"sandbox"**, is used for sandboxed pages instead of the **"shadow"** nCR3. Whenever RIP leaves a sandbox region, the following events occur:


1. #NPF is thrown
2. Switch from **"sandbox"** context -> **"Primary"** context
2. VMM sets RIP to a user-registered callback
3. Execute destination is pushed onto the stack; the instrumentation callback will return to this address
4. All registers are saved
5. guest execution resumes at the callback, in **"Primary"** context

<br>

This mechanism can be used to log the APIs called or exceptions thrown by a module.


#### intercepting out-of-module memory access


I didn't figure out how to log every single memory read and write, because guest page table walks involved reading and writing. I could only properly log reads and writes by denying read/write permissions on specific pages. I had to set up a fourth nCR3: **"all access"**, with every page mapped as RWX. Whenever a read/write instruction in the sandbox is blocked, the following events occur:


1. #NPF is thrown
2. Switch to special **"all access"** context
3. the read/write instruction is single-stepped 
2. Switch from **"all access"** context -> **"Primary"** context
4. VMM sets RIP to a user-registered callback
5. Execute destination is pushed onto the stack; the instrumentation callback will return to this address
6. All registers are saved
7. guest execution resumes at the callback, in **"Primary"** context


#### AetherVisor sandbox vs. other tools


Other projects utilize other methods to achieve the same goal of dynamically analyzing a program in a sandbox:


- **Qiling, Speakeasy:** Uses a CPU emulator to intercept API calls, memory access, and more
- **KACE:** Intercepts access to DLLs and system modules using an exception handler 
- **Simpleator:** Uses Hyper-V API to create an isolated guest address space, and logs Winapi calls


AetherVisor's advantage is that programs don't have to be emulated from the start, and a fabricated system environment doesn't need to be set up. Programs can be sandboxed on-the-fly, allowing you to analyze highly complex software.


### Branch Tracing

The branch tracing feature in AetherVisor uses a combination of Last Branch Record (LBR) and Branch Trap Flag (BTF), to notify the VMM whenever a branch is executed.

The problem with my implementation is that #DB is thrown on every branch, causing a lot of overhead. I thought of collecting branch information in the LBR stack instead of single-stepping every branch, but there's no way to signal when the LBR stack is full on AMD :((((. I considered using Lightweight Profiling (LWP), which has a lot more fine-grained controls for tracing instructions, but it only profiles usermode instructions. Nevertheless, LWP is still a useful feature that can be added later.

When I wanted to test branch tracing, I struggled for hours due to the way VMware and Windows messed with the debugctl MSR.

First of all, VMware was forcing all debugctl bits to 0, which meant that I had to do some testing outside of VMware. 

Secondly, Windows only enables LBR and BTF when the context is switched to a thread with DR7 bits 7 and 8 set, respectively (See KiRestoreDebugRegisterState or whatever). In this manner, Windows manages extended debug features, and my changes this debugctl are essentially ignored. 

### Process-specific syscall hooks


in progress...


## Future plans

I want to use AetherVisor's functionality to create projects like comprehensive HWID spoofers, stealthy DLL injectors, or x64dbg extensions. If I ever decide to extend my hypervisor, I would add LWP and .

