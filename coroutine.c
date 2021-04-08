#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define asmlinkage          __attribute__((regparm(0)))

#define CO_STATE_HALT       1
#define CO_STATE_RUNNING    2
#define CO_STATE_TERMINATED 4

typedef unsigned long     archp;

typedef struct coroutine {
    archp *stack; /* stack alloc pointer addr */
    archp *co_rsp;
    archp *thread_rsp;
    archp ret;
    char  state; /* state & 1 = halt, state & 2 = running, state & 4 = terminated */
} coroutine;

/**
 *  Linux x64 compatible Coroutine implementation
 *
 *  @concept
 *  The basic concept of a coroutine is to able to halt the execution of a function
 *  when `yield` instruction is executed.
 *  Our coroutine will use stack-based trampolines to implement context switching between
 *  main thread execution and coroutine execution.
 *  We need to follow System V AMD64 ABI which is used on Linux which include
 *  save-and-restore RBX/RBP/R12-R15 registers (nonvolatile, callee-saved) in both ways (coroutine enter/coroutine yield|exit)
 *  All others registers must be considered as trash (volatile, caller-saved). (Need some work on this)
 *
 *  @stack-trampoline
 *  A stack trampoline is basically a small set of stack memory which will be used to switch contextes between
 *  a coroutine and the main thread. In his most basic way, it's a [restore-rbp][ret_addr] stack layout.
 */

/**
 *  @function stack_trampoline
 *
 *  This function is the entry point of a context switch
 *  between main thread execution and coroutine execution.

 *  @asmlinkage is needed for the purpose of potential arguments which shouldn't
 *  reside in registers to keep a clean execution.

 *  We save every nonvolatile (callee-saved) registers specified by System V AMD64 ABI
 *  and restore them when the stack trampoline get resumed.

 *  stack_trampoline function switch between two distinct states.

 *  First state is what we will call the `launch state` which basically consists
 *  of invalidating stack registers rsp/rbp with those of elected context.

 *  The second state is what we will call the `recovery state` which basically
 *  is when another higher level stack_trampoline executed his own recovery state.
 *  It'll then recover his own stack context and return silently to his caller context.
 */
asmlinkage archp stack_trampoline(register archp* old_rsp, register archp new_rsp, register archp data) {
    register archp rsp asm("rsp");

    //asm("pushfq"); shouldn't be needed

    // Save callee-saved registers
    asm("push %rbx");
    //asm("push %rbp"); push rbp should be in this function prologue
    asm("push %r12");
    asm("push %r13");
    asm("push %r14");
    asm("push %r15");


    *old_rsp = rsp;
    /* Do stack context switch here */
    asm("mov %0, %%rsp" : : "r" (new_rsp) );
    asm("jc epilogue"); /* Skip context restoring if carry flag is set */

    //asm("popfq"); shouldn't be needed

    // Restore callee-saved registers
    asm("pop %r15");
    asm("pop %r14");
    asm("pop %r13");
    asm("pop %r12");
    //asm("pop %rbp"); pop rbp will be done with this function epilogue
    asm("pop %rbx");

    asm("epilogue:");

    // asm("cld"); /* Since the trampoline should have been called from other function, we do not have to worry about clearing the director flag (DF) which is required by the System V ABI
    return data;
}

/**
 *  coroutine creation process:
 *  0 - call coroutine
 *  1 - coroutine call coroutine_entry()
 *  2 - coroutine_entry() allocate stack, allocate coroutine descriptor, push coroutine context in the coroutine stack, call genesis_trampoline() with descriptor address to return to main thread
 *
 *  what happens with next() ?
 *  somewhere next() is called with the coroutine descriptor then
 *  0 - stack_trampoline save main thread context then restore coroutine one.
 *  1 - stack_trampoline execute the return statement which return to the yield()
 *
 *  what happens with yield() ?
 *  somehwere in a coroutine yield() is called with the value to yield then
 *  0 - stack_trampoline save the coroutine context then restore the main thread one
 *  1 - stack_trampoline execute the return statement which return to the main thread
 */


archp next(coroutine* descriptor, archp value) {
    descriptor->state = CO_STATE_RUNNING;
    asm("clc");
    return stack_trampoline((archp *) &(descriptor->thread_rsp), (archp) descriptor->co_rsp, value);
}

archp yield(archp value, coroutine* descriptor) {
    descriptor->state = CO_STATE_HALT;
    asm("clc");
    return stack_trampoline((archp *) &(descriptor->co_rsp), (archp) descriptor->thread_rsp, value);
}

asmlinkage void co_return_recovery() {
    register archp rax asm("rax");
    coroutine* descriptor = (coroutine *) rax;
    descriptor->state = CO_STATE_TERMINATED;
    asm("clc");
    stack_trampoline((archp *) &(descriptor->co_rsp), (archp) descriptor->thread_rsp, descriptor->ret);
}

void* shadow_addr(void* shadow, void* base, void* offset) {
    return (void *) ( shadow + (offset - base) );
}

/**
 *  @function coroutine_entry
 *  Allocate resources for the coroutine, stack, descriptor object.
 */
archp coroutine_entry(coroutine** this) {
    register archp rsp asm("rsp");
    register archp rbp asm("rbp");

    uint32_t stack_size = 1024 * 4;

    /**
     *  frame address reference:
     *  rbp => current rbp value
     *  *rbp => the rbp value which will be restored in this function epilogue
     *  **rbp => the rbp value which will be restored in this function caller epilogue
     */

    coroutine* co_descriptor = malloc(sizeof(struct coroutine));
    co_descriptor->ret = 0xABCDEF11;
    *this = co_descriptor;

    //printf("descriptor allocated at %p\n", co_descriptor);

    /* set coroutine state to `halt` */ co_descriptor->state = CO_STATE_HALT;

    /* allocate 4KiB stack memory */ co_descriptor->stack = malloc(stack_size);

    /* get coroutine caller frame address */
    archp co_caller_frame_addr = **(archp **) rbp;

    /* compute coroutine stack frame size + co_caller stack frame size */
    uint32_t delta_size = co_caller_frame_addr - rsp;

    if ( delta_size > stack_size ) {
        /* co_caller stack frame size + coroutine stack frame size exceed the allocated stack size which result in a stack overflow */
        printf("Coroutine stack overflow in coroutine_entry().");
    }

    co_descriptor->co_rsp = (archp *) ((archp) co_descriptor->stack + stack_size) - delta_size;

    archp main_thread_restore_stack_pointer = *(archp *) rbp;
    archp patch_rbp = (archp) shadow_addr(co_descriptor->co_rsp, (void *) rsp, (void *) main_thread_restore_stack_pointer);
    archp* shadow_rbp = shadow_addr(co_descriptor->co_rsp, (void *) rsp, (void *) rbp);

    //printf("coroutine entry rbp restore patched with %p\n", patch_rbp);

    /* Do copy */ memcpy(co_descriptor->co_rsp, (void *) rsp, delta_size);

    /* Patch coroutine_entry restore rbp */ *shadow_rbp = patch_rbp;
    /* Patch coroutine restore rbp with "trash" rbp */ ** (archp **) shadow_rbp = patch_rbp;
    /* Patch coroutine ret daddr */ * ( ( * (archp **) shadow_rbp ) + 1 ) = (archp) &co_return_recovery;

    /* Switch stack context before calling genesis trampoline ... */
    rsp = (archp) co_descriptor->co_rsp;
    asm("mov %0, %%rbp" : : "r" (shadow_rbp));

    asm("stc");
    return stack_trampoline((archp *) &(co_descriptor->co_rsp), main_thread_restore_stack_pointer, (archp) co_descriptor);
}

archp* saved_base_ptr_level(archp* base, int level) {
    while ( level-- )
        base = (archp *) *base;
    return base;
}

coroutine* fork_state_machine(uint32_t pid) {
    coroutine* this;
    coroutine_entry(&this);

    if ( pid == 0 ) {
        uint32_t n = 1;
        printf("Forked coroutine\n");
        while ( 1 ) {
            yield(n, this);
            n += 2;
        }
    }
    else {
        coroutine* child = fork_state_machine(0);
        uint32_t n = 0;
        printf("Parent coroutine.\n");
        while ( 1 ) {
            yield(n, this);
            yield(next(child, 0), this);
            n += 2;
        }
    }

    return this;
}

int main(void) {
    coroutine* counter = fork_state_machine(100);

    printf("counter descriptor: %p\n", counter);
    int i = 0;
    while ( !(counter->state & CO_STATE_TERMINATED) && i++ < 100 )
        printf("-> %d\n", next(counter, 0));

    return 0;
}
