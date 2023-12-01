#include "kernel.h"
#include "lib.h"

// kernel.c
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

static proc processes[NPROC];   // array of process descriptors
                                // Note that `processes[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static unsigned ticks;          // # timer interrupts so far

void schedule(void);
void run(proc* p) __attribute__((noreturn));

static uint8_t disp_global = 1;         // global flag to display memviewer

static physical_pageinfo pageinfo[PAGENUMBER(MEMSIZE_PHYSICAL)];

static void pageinfo_init(void);


// Memory functions

void check_virtual_memory(void);
void memshow_physical(void);
void memshow_virtual(x86_64_pagetable* pagetable, const char* name);
void memshow_virtual_animate(void);


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, int program_number);

// Allocating and inititalizing page tables
int setup_process_pagetable(proc* process);

void kernel(const char* command) {
    hardware_init();
    pageinfo_init();
    console_clear();
    timer_init(HZ);


    // Set up process descriptors
    memset(processes, 0, sizeof(processes));
    for (pid_t i = 0; i < NPROC; i++) {
        processes[i].p_pid = i;
        processes[i].p_state = P_FREE;
    }

    if (command && strcmp(command, "fork") == 0) {
        process_setup(1, 4);
    } else if (command && strcmp(command, "forkexit") == 0) {
        process_setup(1, 5);
    } else if (command && strcmp(command, "test") == 0) {
        process_setup(1, 6);
    } else if (command && strcmp(command, "test2") == 0) {
        for (pid_t i = 1; i <= 2; ++i) {
            process_setup(i, 6);
        }
    } else {
        for (pid_t i = 1; i <= 4; ++i) {
            process_setup(i, i - 1);
        }
    }


    // Switch to the first process using run()
    run(&processes[1]);
}


// process_setup(pid, program_number)
//    Load application program `program_number` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, int program_number) {
    proc* p = &processes[pid];
    process_init(p, 0);

    // Set up an independent page table for this process
    int result = setup_process_pagetable(p);
    assert(result >= 0); // Ensure that page table setup was successful

    // Load the program into the process's address space
    int r = program_load(p, program_number, p->p_pagetable);
    assert(r >= 0);

    // Set up process stack at 0x300000 (MEMSIZE_VIRTUAL)
    p->p_registers.reg_rsp = MEMSIZE_VIRTUAL;
    uintptr_t stack_page = p->p_registers.reg_rsp - PAGESIZE;
    assign_physical_page(stack_page, pid);
    virtual_memory_map(p->p_pagetable, stack_page, stack_page,
                       PAGESIZE, PTE_P | PTE_W | PTE_U);

    // Mark the process as runnable
    p->p_state = P_RUNNABLE;
}






// Function to allocate the next available free physical page
uintptr_t allocate_free_physical_page() {
    for (size_t i = 0; i < NPAGES; ++i) {
        if (pageinfo[i].refcount == 0) {
            // Found a free page
            uintptr_t addr = i * PAGESIZE;
            // Mark the page as used in the pageinfo array
            pageinfo[i].refcount = 1;
            pageinfo[i].owner = PO_KERNEL; // Or use appropriate owner
            return addr;
        }
    }
    // No free page found
    return 0;
}

// Allocate physical page
uintptr_t allocate_physical_page() {
    for (size_t i = 0; i < NPAGES; ++i) {
        if (pageinfo[i].refcount == 0) {
            // Found a free page
            uintptr_t addr = i * PAGESIZE;
            if (assign_physical_page(addr, KERNEL_PID) == 0) {
                // Successfully assigned the page
                return addr;
            }
        }
    }
    // No free page found
    return 0;
}

// Helper function to allocate and zero a page table
static x86_64_pagetable* allocate_zeroed_pagetable() {
    uintptr_t page_addr = allocate_physical_page();
    if (page_addr == 0) return NULL;  // Allocation failed

    x86_64_pagetable* table = (x86_64_pagetable*) PAGEADDRESS(page_addr);
    memset(table, 0, PAGESIZE);
    return table;
}

// Function to copy pagetable
x86_64_pagetable* copy_pagetable(x86_64_pagetable* old_pagetable, pid_t new_pid) {
    // Allocate new page tables for the child
    x86_64_pagetable* new_pagetable = allocate_zeroed_pagetable();
    if (!new_pagetable) return NULL;

    // Iterate over each entry in the old pagetable and copy if necessary
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(old_pagetable, va);
        if (vmap.perm & PTE_P) {
            // Allocate a new physical page for the child
            uintptr_t new_pa = allocate_physical_page();
            if (!new_pa) {
                // Handle allocation failure
                free_pagetable(new_pagetable);
                return NULL;
            }

            // Update pageinfo for the new physical page
            int new_page_number = PAGENUMBER(new_pa);
            pageinfo[new_page_number].owner = new_pid;
            pageinfo[new_page_number].refcount = 1;

            // Copy data from the parent's page
            memcpy((void*) new_pa, (void*) vmap.pa, PAGESIZE);

            // Map the new page in the child's pagetable
            int result = virtual_memory_map(new_pagetable, va, new_pa, PAGESIZE, vmap.perm);
            if (result < 0) {
                // Handle mapping failure
                free_physical_page(new_pa);
                free_pagetable(new_pagetable);
                return NULL;
            }
        }
    }

    return new_pagetable;
}

// Helper function to free pagetable and associated pages
void free_pagetable(x86_64_pagetable* pagetable) {
    // Iterate over all entries and free any allocated pages
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(pagetable, va);
        if (vmap.perm & PTE_P) {
            free_physical_page(vmap.pa);
        }
    }
    // Finally, free the pagetable itself
    free_physical_page((uintptr_t) pagetable);
}

// Helper function to free a physical page and update pageinfo
void free_physical_page(uintptr_t pa) {
    int pn = PAGENUMBER(pa);
    if (pageinfo[pn].refcount > 0) {
        pageinfo[pn].refcount--;
        if (pageinfo[pn].refcount == 0) {
            pageinfo[pn].owner = PO_FREE;
        }
    }
}

// Helper function to free process' resources used by sys_exit
void free_process_resources(proc* process) {
    // Free all pages used by the process
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(process->p_pagetable, va);
        if (vmap.perm & PTE_P) {
            // Decrement the reference count
            int pn = PAGENUMBER(vmap.pa);
            pageinfo[pn].refcount--;
            // If refcount reaches 0, mark the page as free
            if (pageinfo[pn].refcount == 0) {
                pageinfo[pn].owner = PO_FREE;
            }
        }
    }

    // Free the page table pages used by the process
    free_pagetable(process->p_pagetable);
    process->p_pagetable = NULL;
}


// Function to setup process pagetables and map 3MB of virtual memory
int setup_process_pagetable(proc* process) {
    // Allocate and zero L4, L3, L2, and two L1 tables
    x86_64_pagetable *l4, *l3, *l2, *l1_1, *l1_2;
    l4 = allocate_zeroed_pagetable(); if (!l4) return -1;
    l3 = allocate_zeroed_pagetable(); if (!l3) goto free_l4;
    l2 = allocate_zeroed_pagetable(); if (!l2) goto free_l3;
    l1_1 = allocate_zeroed_pagetable(); if (!l1_1) goto free_l2;
    l1_2 = allocate_zeroed_pagetable(); if (!l1_2) goto free_l1_1;

    // Setup hierarchy: L4 -> L3 -> L2 -> L1
    l4->entry[0] = (uintptr_t) l3 | PTE_P | PTE_W | PTE_U;
    l3->entry[0] = (uintptr_t) l2 | PTE_P | PTE_W | PTE_U;
    l2->entry[0] = (uintptr_t) l1_1 | PTE_P | PTE_W | PTE_U;
    l2->entry[1] = (uintptr_t) l1_2 | PTE_P | PTE_W | PTE_U;

    // Map 3MB of virtual memory using L1 tables
    for (int i = 0; i < 512; ++i) {
        l1_1->entry[i] = (i * PAGESIZE) | PTE_P | PTE_W | PTE_U; // First 2MB
        if (i < 256) {
            l1_2->entry[i] = ((512 + i) * PAGESIZE) | PTE_P | PTE_W | PTE_U; // Next 1MB
        }
    }

    // Copy kernel mappings
    for (uintptr_t va = 0; va < PROC_START_ADDR; va += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(kernel_pagetable, va);
        if (vmap.perm & PTE_P) {
            virtual_memory_map(l4, va, vmap.pa, PAGESIZE, vmap.perm);
        }
    }

    process->p_pagetable = l4;
    return 0;

    // Cleanup in case of allocation failure
free_l1_1: free_physical_page((uintptr_t) l1_1);
free_l2:   free_physical_page((uintptr_t) l2);
free_l3:   free_physical_page((uintptr_t) l3);
free_l4:   free_physical_page((uintptr_t) l4);
    return -1;
}


// assign_physical_page(addr, owner)
//    Allocates the page with physical address `addr` to the given owner.
//    Fails if physical page `addr` was already allocated. Returns 0 on
//    success and -1 on failure. Used by the program loader.

int assign_physical_page(uintptr_t addr, int8_t owner) {
    if ((addr & 0xFFF) != 0
        || addr >= MEMSIZE_PHYSICAL
        || pageinfo[PAGENUMBER(addr)].refcount != 0) {
        return -1;
    } else {
        pageinfo[PAGENUMBER(addr)].refcount = 1;
        pageinfo[PAGENUMBER(addr)].owner = owner;
        return 0;
    }
}

void syscall_mapping(proc* p){

    uintptr_t mapping_ptr = p->p_registers.reg_rdi;
    uintptr_t ptr = p->p_registers.reg_rsi;

    //convert to physical address so kernel can write to it
    vamapping map = virtual_memory_lookup(p->p_pagetable, mapping_ptr);

    // check for write access
    if((map.perm & (PTE_W|PTE_U)) != (PTE_W|PTE_U))
        return;
    uintptr_t endaddr = mapping_ptr + sizeof(vamapping) - 1;
    // check for write access for end address
    vamapping end_map = virtual_memory_lookup(p->p_pagetable, endaddr);
    if((end_map.perm & (PTE_W|PTE_P)) != (PTE_W|PTE_P))
        return;
    // find the actual mapping now
    vamapping ptr_lookup = virtual_memory_lookup(p->p_pagetable, ptr);
    memcpy((void *)map.pa, &ptr_lookup, sizeof(vamapping));
}

void syscall_mem_tog(proc* process){

    pid_t p = process->p_registers.reg_rdi;
    if(p == 0) {
        disp_global = !disp_global;
    }
    else {
        if(p < 0 || p > NPROC || p != process->p_pid)
            return;
        process->display_status = !(process->display_status);
    }
}

// exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `reg`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled whenever the kernel is running.

void exception(x86_64_registers* reg) {
    // Copy the saved registers into the `current` process descriptor
    // and always use the kernel's page table.
    current->p_registers = *reg;
    set_pagetable(kernel_pagetable);

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /*log_printf("proc %d: exception %d\n", current->p_pid, reg->reg_intno);*/

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if ((reg->reg_intno != INT_PAGEFAULT && reg->reg_intno != INT_GPF) // no error due to pagefault or general fault
            || (reg->reg_err & PFERR_USER)) // pagefault error in user mode 
    {
        check_virtual_memory();
        if(disp_global){
            memshow_physical();
            memshow_virtual_animate();
        }
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (reg->reg_intno) {

    case INT_SYS_FORK: {
    // Find a free process slot (skip slot 0)
    pid_t child_pid = -1;
    for (pid_t i = 1; i < NPROC; ++i) {
        if (processes[i].p_state == P_FREE) {
            child_pid = i;
            break;
        }
    }

    if (child_pid == -1) {
        // No free process slot found
        current->p_registers.reg_rax = -1;
        break;
    }

    // Initialize child process
    proc* child = &processes[child_pid];
    process_init(child, 0);
    child->p_state = P_RUNNABLE;

    // Copy the page table of the parent process
    child->p_pagetable = copy_pagetable(current->p_pagetable, child_pid);
    if (child->p_pagetable == NULL) {
        // Handle failed page table copy
        child->p_state = P_FREE;
        current->p_registers.reg_rax = -1;
        break;
    }

    // Duplicate process data in every application page
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(current->p_pagetable, va);
        if (vmap.perm & PTE_P && vmap.perm & PTE_U) {
            uintptr_t new_pa;

            // If page is read-only, share it; otherwise, allocate a new page
            if (!(vmap.perm & PTE_W)) { 
                new_pa = vmap.pa; // Share the physical page
                pageinfo[PAGENUMBER(new_pa)].refcount++; // Increment refcount
            } else {
                // Allocate a new physical page for writable pages
                new_pa = allocate_physical_page();
                if (new_pa == 0) {
                    // Handle out of memory
                    free_pagetable(child->p_pagetable);
                    child->p_state = P_FREE;
                    current->p_registers.reg_rax = -1;
                    break;
                }
                // Copy the data from the parent's page into the new page
                memcpy((void*) new_pa, (void*) vmap.pa, PAGESIZE);
            }

            // Map the page in the child's page table
            int mapping_perm = vmap.perm;
            if (!(vmap.perm & PTE_W)) {
                // Enforce read-only permissions for shared pages
                mapping_perm &= ~PTE_W;
            }
            virtual_memory_map(child->p_pagetable, va, new_pa, PAGESIZE, mapping_perm);
        }
    }

    // Initialize child's registers (copy from parent)
    child->p_registers = current->p_registers;
    child->p_registers.reg_rax = 0; // Child process's fork returns 0

    // Return child's PID to the parent
    current->p_registers.reg_rax = child_pid;
    break;
}

    case INT_SYS_EXIT:
        // Call function to free all memory used by the process
        free_process_resources(current);

        // Mark the process as free
        current->p_state = P_FREE;
        // Switch to the next process
        schedule();
        break;

    case INT_SYS_PANIC:
	    // rdi stores pointer for msg string
	    {
		char msg[160];
		uintptr_t addr = current->p_registers.reg_rdi;
		if((void *)addr == NULL)
		    panic(NULL);
		vamapping map = virtual_memory_lookup(current->p_pagetable, addr);
		memcpy(msg, (void *)map.pa, 160);
		panic(msg);

	    }
	    panic(NULL);
	    break;                  // will not be reached

    case INT_SYS_GETPID:
        current->p_registers.reg_rax = current->p_pid;
        break;

    case INT_SYS_YIELD:
        schedule();
        break;                  /* will not be reached */

case INT_SYS_PAGE_ALLOC: {
    uintptr_t addr = current->p_registers.reg_rdi;
    
    // Check if 'addr' is within user space and page-aligned
    if (addr < USER_SPACE_START || addr >= USER_SPACE_END || addr % PAGESIZE != 0) {
        current->p_registers.reg_rax = -1;  // Invalid address or not aligned
        break;
    }

    // Allocate a physical page
    uintptr_t physical_page = allocate_physical_page();
    if (physical_page == 0) {
        // No physical memory available
        console_printf(CPOS(24, 0), 0x0C00, "Out of physical memory!\n");
        current->p_registers.reg_rax = -1;  // Allocation failed
        break;
    }

    // Map the allocated physical page to the requested virtual address
    int map_result = virtual_memory_map(current->p_pagetable, addr, physical_page, PAGESIZE, PTE_P | PTE_W | PTE_U);
    if (map_result < 0) {
        free_physical_page(physical_page);  // Free the allocated page
        current->p_registers.reg_rax = -1;  // Mapping failed
    } else {
        current->p_registers.reg_rax = 0;   // Success
    }
    break;
}

    case INT_SYS_MAPPING:
    {
	    syscall_mapping(current);
            break;
    }

    case INT_SYS_MEM_TOG:
	{
	    syscall_mem_tog(current);
	    break;
	}

    case INT_TIMER:
        ++ticks;
        schedule();
        break;                  /* will not be reached */

    case INT_PAGEFAULT: {
        // Analyze faulting address and access type.
        uintptr_t addr = rcr2();
        const char* operation = reg->reg_err & PFERR_WRITE
                ? "write" : "read";
        const char* problem = reg->reg_err & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(reg->reg_err & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, reg->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->p_pid, addr, operation, problem, reg->reg_rip);
        current->p_state = P_BROKEN;
        break;
    }

    default:
        default_exception(current);
        break;                  /* will not be reached */

    }


    // Return to the current process (or run something else).
    if (current->p_state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule(void) {
    pid_t pid = current->p_pid;
    while (1) {
        pid = (pid + 1) % NPROC;
        if (processes[pid].p_state == P_RUNNABLE) {
            run(&processes[pid]);
        }
        // If Control-C was typed, exit the virtual machine.
        check_keyboard();
    }
}


// run(p)
//    Run process `p`. This means reloading all the registers from
//    `p->p_registers` using the `popal`, `popl`, and `iret` instructions.
//
//    As a side effect, sets `current = p`.

void run(proc* p) {
    assert(p->p_state == P_RUNNABLE);
    current = p;

    // Load the process's current pagetable.
    set_pagetable(p->p_pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(&p->p_registers);

 spinloop: goto spinloop;       // should never get here
}


// pageinfo_init
//    Initialize the `pageinfo[]` array.

void pageinfo_init(void) {
    extern char end[];

    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int owner;
        if (physical_memory_isreserved(addr)) {
            owner = PO_RESERVED;
        } else if ((addr >= KERNEL_START_ADDR && addr < (uintptr_t) end)
                   || addr == KERNEL_STACK_TOP - PAGESIZE) {
            owner = PO_KERNEL;
        } else {
            owner = PO_FREE;
        }
        pageinfo[PAGENUMBER(addr)].owner = owner;
        pageinfo[PAGENUMBER(addr)].refcount = (owner != PO_FREE);
    }
}


// check_page_table_mappings
//    Check operating system invariants about kernel mappings for page
//    table `pt`. Panic if any of the invariants are false.

void check_page_table_mappings(x86_64_pagetable* pt) {
    extern char start_data[], end[];
    assert(PTE_ADDR(pt) == (uintptr_t) pt);

    // kernel memory is identity mapped; data is writable
    for (uintptr_t va = KERNEL_START_ADDR; va < (uintptr_t) end;
         va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pt, va);
        if (vam.pa != va) {
            console_printf(CPOS(22, 0), 0xC000, "%p vs %p\n", va, vam.pa);
        }
        assert(vam.pa == va);
        if (va >= (uintptr_t) start_data) {
            assert(vam.perm & PTE_W);
        }
    }

    // kernel stack is identity mapped and writable
    uintptr_t kstack = KERNEL_STACK_TOP - PAGESIZE;
    vamapping vam = virtual_memory_lookup(pt, kstack);
    assert(vam.pa == kstack);
    assert(vam.perm & PTE_W);
}


// check_page_table_ownership
//    Check operating system invariants about ownership and reference
//    counts for page table `pt`. Panic if any of the invariants are false.

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount);

void check_page_table_ownership(x86_64_pagetable* pt, pid_t pid) {
    // calculate expected reference count for page tables
    int owner = pid;
    int expected_refcount = 1;
    if (pt == kernel_pagetable) {
        owner = PO_KERNEL;
        for (int xpid = 0; xpid < NPROC; ++xpid) {
            if (processes[xpid].p_state != P_FREE
                && processes[xpid].p_pagetable == kernel_pagetable) {
                ++expected_refcount;
            }
        }
    }
    check_page_table_ownership_level(pt, 0, owner, expected_refcount);
}

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount) {
    assert(PAGENUMBER(pt) < NPAGES);
    assert(pageinfo[PAGENUMBER(pt)].owner == owner);
    assert(pageinfo[PAGENUMBER(pt)].refcount == refcount);
    if (level < 3) {
        for (int index = 0; index < NPAGETABLEENTRIES; ++index) {
            if (pt->entry[index]) {
                x86_64_pagetable* nextpt =
                    (x86_64_pagetable*) PTE_ADDR(pt->entry[index]);
                check_page_table_ownership_level(nextpt, level + 1, owner, 1);
            }
        }
    }
}


// check_virtual_memory
//    Check operating system invariants about virtual memory. Panic if any
//    of the invariants are false.

void check_virtual_memory(void) {
    // Process 0 must never be used.
    assert(processes[0].p_state == P_FREE);

    // The kernel page table should be owned by the kernel;
    // its reference count should equal 1, plus the number of processes
    // that don't have their own page tables.
    // Active processes have their own page tables. A process page table
    // should be owned by that process and have reference count 1.
    // All level-2-4 page tables must have reference count 1.

    check_page_table_mappings(kernel_pagetable);
    check_page_table_ownership(kernel_pagetable, -1);

    for (int pid = 0; pid < NPROC; ++pid) {
        if (processes[pid].p_state != P_FREE
            && processes[pid].p_pagetable != kernel_pagetable) {
            check_page_table_mappings(processes[pid].p_pagetable);
            check_page_table_ownership(processes[pid].p_pagetable, pid);
        }
    }

    // Check that all referenced pages refer to active processes
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pageinfo[pn].refcount > 0 && pageinfo[pn].owner >= 0) {
            assert(processes[pageinfo[pn].owner].p_state != P_FREE);
        }
    }
}

// memshow_physical
//    Draw a picture of physical memory on the CGA console.

static const uint16_t memstate_colors[] = {
    'K' | 0x0D00, 'R' | 0x0700, '.' | 0x0700, '1' | 0x0C00,
    '2' | 0x0A00, '3' | 0x0900, '4' | 0x0E00, '5' | 0x0F00,
    '6' | 0x0C00, '7' | 0x0A00, '8' | 0x0900, '9' | 0x0E00,
    'A' | 0x0F00, 'B' | 0x0C00, 'C' | 0x0A00, 'D' | 0x0900,
    'E' | 0x0E00, 'F' | 0x0F00, 'S'
};
#define SHARED_COLOR memstate_colors[18]
#define SHARED

void memshow_physical(void) {
    console_printf(CPOS(0, 32), 0x0F00, "PHYSICAL MEMORY");
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pn % 64 == 0) {
            console_printf(CPOS(1 + pn / 64, 3), 0x0F00, "0x%06X ", pn << 12);
        }

        int owner = pageinfo[pn].owner;
        if (pageinfo[pn].refcount == 0) {
            owner = PO_FREE;
        }
        uint16_t color = memstate_colors[owner - PO_KERNEL];
        // darker color for shared pages
        if (pageinfo[pn].refcount > 1 && pn != PAGENUMBER(CONSOLE_ADDR)){
#ifdef SHARED
            color = SHARED_COLOR | 0x0F00;
#else
	    color &= 0x77FF;
#endif
        }

        console[CPOS(1 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual(pagetable, name)
//    Draw a picture of the virtual memory map `pagetable` (named `name`) on
//    the CGA console.

void memshow_virtual(x86_64_pagetable* pagetable, const char* name) {
    assert((uintptr_t) pagetable == PTE_ADDR(pagetable));

    console_printf(CPOS(10, 26), 0x0F00, "VIRTUAL ADDRESS SPACE FOR %s", name);
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pagetable, va);
        uint16_t color;
        if (vam.pn < 0) {
            color = ' ';
        } else {
            assert(vam.pa < MEMSIZE_PHYSICAL);
            int owner = pageinfo[vam.pn].owner;
            if (pageinfo[vam.pn].refcount == 0) {
                owner = PO_FREE;
            }
            color = memstate_colors[owner - PO_KERNEL];
            // reverse video for user-accessible pages
            if (vam.perm & PTE_U) {
                color = ((color & 0x0F00) << 4) | ((color & 0xF000) >> 4)
                    | (color & 0x00FF);
            }
            // darker color for shared pages
            if (pageinfo[vam.pn].refcount > 1 && va != CONSOLE_ADDR) {
#ifdef SHARED
                color = (SHARED_COLOR | (color & 0xF000));
                if(! (vam.perm & PTE_U))
                    color = color | 0x0F00;

#else
		color &= 0x77FF;
#endif
            }
        }
        uint32_t pn = PAGENUMBER(va);
        if (pn % 64 == 0) {
            console_printf(CPOS(11 + pn / 64, 3), 0x0F00, "0x%06X ", va);
        }
        console[CPOS(11 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual_animate
//    Draw a picture of process virtual memory maps on the CGA console.
//    Starts with process 1, then switches to a new process every 0.25 sec.

void memshow_virtual_animate(void) {
    static unsigned last_ticks = 0;
    static int showing = 1;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        ++showing;
    }

    // the current process may have died -- don't display it if so
    while (showing <= 2*NPROC
           && (processes[showing % NPROC].p_state == P_FREE || processes[showing % NPROC].display_status == 0)) {
        ++showing;
    }
    showing = showing % NPROC;

    if (processes[showing].p_state != P_FREE) {
        char s[4];
        snprintf(s, 4, "%d ", showing);
        memshow_virtual(processes[showing].p_pagetable, s);
    }
}
