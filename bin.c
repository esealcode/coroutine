#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define asmlinkage          __attribute__((regparm(0)))
#define ARCH_MEM            sizeof(void *)
#define YIELD_STACK_SIZE    4096 /* Align on a standard system page size */
#define STD_FILE_ERR        2    /* stderr */
#define yield(v)            _yield((wide_reg) v)
#define yi_placeholder      NULL

typedef unsigned long   wide_reg;
typedef unsigned long*  iso_stack_ptr_t;

typedef enum bool
{
    false, true
}
bool;

typedef struct stack_epilogue stack_epilogue;
struct stack_epilogue {
    struct stack_epilogue*  caller_frame_address;
    wide_reg*               rest_ip;
};

typedef struct registers registers;
struct registers {
    void*       stack_pointer;
    void*       frame_address;
};

typedef struct yielder yielder;
struct yielder {
    wide_reg        value;
    bool            done;
    registers       regs;
    registers       traceback_regs;
    yielder*        traceback;
    iso_stack_ptr_t iso_stack;
    iso_stack_ptr_t iso_stack_base;
};

typedef struct Generator {
    yielder* track;
    yielder* allocated;
} Generator;

Generator G = {NULL, NULL};

void stack_print(void* stack, short on) {
    wide_reg* _stack = stack;
    while ( on-- ) {
        printf("0x%016lx ", *(_stack++));
        if ( on % 4 == 0 )
            printf("\n");
    }
}

void yield_alloc_panic(char* msg) {
    write(STD_FILE_ERR, msg, strlen(msg));
}

/*
 *  __alloc_yielder_resources: Function which allocate resources for a new generator.
 *  @return: Generator object.
 *
 *  @context:
 *              +--------------+
 *              |  alloc_stack |
 *              +--------------+
 *              |   ep_stack   |
 *              +--------------+
 *              |   g_stack    |
 *              +--------------+
 *              | g_call_stack |
 *              +--------------+
 */
yielder* __alloc_yielder_resources(short min_stack_size) {
    yielder* new;
    printf("min_stack_size: %d, OK ?: %d\n", min_stack_size, min_stack_size < YIELD_STACK_SIZE);
    if ( min_stack_size > YIELD_STACK_SIZE ) {
        yield_alloc_panic("__alloc_yielder_resources cannot allocate more than %d bytes for the isolated stack.\n");
        return NULL;
    }

    new = (yielder *) malloc(sizeof(struct yielder));
    if ( new == NULL ) {
        yield_alloc_panic("__alloc_yielder_resources cannot allocate memory for yielder object.\n");
        return NULL;
    }

    new->iso_stack = (iso_stack_ptr_t) malloc(YIELD_STACK_SIZE);
    if ( new->iso_stack == NULL ) {
        yield_alloc_panic("__alloc_yielder_resources cannot allocate memory for isolated stack.\n");
        free(new);
        return NULL;
    }

    new->iso_stack_base = new->iso_stack + YIELD_STACK_SIZE;

    new->value = 0;
    new->done = false;
    new->regs.stack_pointer = new->iso_stack_base;
    new->regs.frame_address = new->iso_stack_base;

    return new;
}

/*
 *  Standard isolated stack utils functions.
 */
void iso_stack_alloc(yielder* yi, wide_reg l) {
    yi->regs.stack_pointer = ((char *) (yi->regs.stack_pointer) - l);
}

void iso_stack_unalloc(yielder* yi, wide_reg l) {
    yi->regs.stack_pointer = ((char *) (yi->regs.stack_pointer) + l);
}

/*
 *  __bridge_stack: Function which will switch stack context,
 *                  and implicitly keep next()/yield() execution
 *                  context for resuming it later.
 */
asmlinkage void __bridge_stack(registers* regs, wide_reg* stack_pointer, wide_reg* frame_address) {
    wide_reg* bridge_stack_pointer;
    wide_reg* bridge_frame_address;
    asm (   "mov %%rsp, %0\n\t"
            "mov %%rbp, %1\n\t"
            : "=r" (bridge_stack_pointer), "=r" (bridge_frame_address) );

    regs->stack_pointer = bridge_stack_pointer;
    regs->frame_address = bridge_frame_address;

    asm (   "mov %0, %%rsp\n\t"
            "mov %1, %%rbp\n\t"
            "leave\n\t"
            "ret"
            : : "r" (stack_pointer), "r" (frame_address) );
}

/*
 *  __endpoint: Function which handle generator return, and return execution to the right address.
 *  &__endpoint will be the standard return address on every generator stack frame.
 *
 *  @context:
 *              +----------------+
 *              | endpoint_stack |
 *              +----------------+
 *              |    g_stack     |
 *              +----------------+
 */
void __endpoint() {
    G.track->done = true;
    G.track->value = 0;
    __bridge_stack(&G.track->regs, G.track->traceback_regs.stack_pointer, G.track->traceback_regs.frame_address);
}

/*
 *  entry_point: Function which handle generator entry breakpoint, allocate resources for generator, and
 *               return identifier.
 *  @context:
 *              +--------------+
 *              |   ep_stack   |
 *              +--------------+
 *              |   g_stack    |
 *              +--------------+
 *              | g_call_stack |
 *              +--------------+
 */
void entry_point() {
    /* Fetch current stack epilogue (of entry_point) */
    stack_epilogue* entry_sep = __builtin_frame_address(0);

    /*
     *  Fetch yielder stack pointer (RSP) and yielder caller frame address, then compute the difference
     *  1 * sizeof(stack_epilogue) skips : CALL ... (push RIP), PUSH RBP to get original yielder stack pointer
     *  before entry_point was called
     */
    wide_reg* yi_stack_pointer = (wide_reg *) (entry_sep + 1);
    wide_reg* yi_caller_frame_address = (wide_reg *) entry_sep->caller_frame_address->caller_frame_address;
    wide_reg frames_range = (wide_reg) yi_caller_frame_address - (wide_reg) yi_stack_pointer;

    /*
     *  Allocate isolated stack and yielder object, get the yielder resume address after entry_point and save it
     *  in yielder object context.
     */
    yielder* yi = __alloc_yielder_resources(frames_range);

    /*
     *  Alloc stack space on isolated stack to hold yielder + yielder caller stack frames.
     */
    iso_stack_alloc(yi, frames_range);
    //printf("Isolated stack pointer at 0x%lx\n", yi->regs.stack_pointer);

    /*
     *  Copy stack frames from isolated stack pointer
     */
    memcpy(yi->regs.stack_pointer, yi_stack_pointer, frames_range);

    /*
     *  Compute the new yielder frame address for future execution resume (keep frame address aligned with parameters and local arguments)
     */
    yi->regs.frame_address = ( yi->regs.stack_pointer +
                             ( (wide_reg) entry_sep->caller_frame_address - (wide_reg) yi_stack_pointer ));
    //printf("Computed isolated stack yielder frame address: 0x%lx\n", yi->regs.frame_address);

    /*
     *  Debug print
     */
    //stack_print(yi->regs.stack_pointer, 32);

    //printf("Yi ret addr validation: 0x%lx\n", *(wide_reg *)(yi->regs.frame_address + ARCH_MEM));
    //printf("Patch Yi rest_ip with &__endpoint (0x%lx) ...\n", &__endpoint);

    /*
     *  Patch return address in isolated stack with &__endpoint which is the function which handle yielder returns.
     */
    *(wide_reg *)(yi->regs.frame_address + ARCH_MEM) = (wide_reg) &__endpoint;
    //printf("Yi ret addr after patch: 0x%lx\n", *(wide_reg *)(yi->regs.frame_address + ARCH_MEM));

    /*
     *  Alloc stack space for yielder resume epilogue, and patch memory with right frame address + resume ip address
     */
    iso_stack_alloc(yi, sizeof(struct stack_epilogue));
    stack_epilogue* next_epilogue = (stack_epilogue *) yi->regs.stack_pointer;
    next_epilogue->caller_frame_address = (struct stack_epilogue *) yi->regs.frame_address;
    next_epilogue->rest_ip = (wide_reg *) entry_sep->rest_ip;
    yi->regs.frame_address = yi->regs.stack_pointer;
    printf("next epilogue frame address: 0x%lx, rest_ip: 0x%lx\n", *(wide_reg *)(yi->regs.frame_address), *(wide_reg *)(yi->regs.frame_address + ARCH_MEM));


    /*
     *  Get the yielder restore frame address, then execute raw ASM to return to yielder caller with yielder object as return value.
     */
    wide_reg restore_frame_address = (wide_reg) entry_sep->caller_frame_address;
    printf("Resume information\n\trax: 0x%lx, rsp: 0x%lx\n", (wide_reg) yi, restore_frame_address);

    /*
     *  Architecture specific assembly code
     */
    asm (   "mov %0, %%rax\n\t" /* Return value, yielder object address         */
            "mov %1, %%rsp\n\t" /* Align stack pointer on yielder frame address */
            "pop %%rbp\n\t"     /* Restore yielder caller frame address         */
            "ret"               /* Resume yielder caller execution              */
            : : "r" (yi), "r" (restore_frame_address) );
}

/*
 *  return_with_value: Function which simulate a return instruction for a yielder.
 */
void return_with_value(wide_reg rax) {
    G.track->value = rax;
    G.track->done = true;
      __bridge_stack(&G.track->regs, G.track->traceback_regs.stack_pointer, G.track->traceback_regs.frame_address);
}

/*
 *  next: Function which will resume generator isolated execution, performing stack context switch.
 *  @return: yield value.
 */
wide_reg next(yielder* yi) {
    /*
     *  Current yielder in execution is now `yi`
     */
    if ( yi->done )
      return 0;
    yi->traceback = G.track;
    G.track = yi;
    __bridge_stack(&yi->traceback_regs, yi->regs.stack_pointer, yi->regs.frame_address);
    G.track = yi->traceback;
    yi->traceback_regs.stack_pointer = NULL;
    yi->traceback_regs.frame_address = NULL;

    return yi->value;
}

/*
 *  yield: Function which will be called by generators to yield a value.
 */
void _yield(wide_reg v) {
    G.track->value = v;
    __bridge_stack(&G.track->regs, G.track->traceback_regs.stack_pointer, G.track->traceback_regs.frame_address);
}

yielder* checkMapAlignement(void* ptr) {
  entry_point();
  wide_reg* _ptr = ptr;
  while (1) {
    yield((*_ptr) % 16);
  }
  return yi_placeholder;
}

yielder* secureMap(int page_size, int bound) {
    entry_point(); /* Declare new generator instance, and return to caller */
    printf("Secure map after entryPoint :)\n");
    void* alloc;
    yielder* checker = checkMapAlignement(&alloc);
    while ( bound-- ) {
      alloc = malloc(page_size);
      if ( next(checker) != 0 )
        printf("/!\\ Warning : Allocated memory isn't 16-bytes aligned.\n");
      yield(alloc);
    }
    printf("secureMap bound reached. Bye :)\n");
    return yi_placeholder;
}

yielder* stillAvailable(int x) {
  entry_point();
  int iso_stack_x = x;
  yield(&x);
  yield(&iso_stack_x);
  while ( 1 )
    yield(iso_stack_x++);
}

yielder* give_me_message(char** buf) {
  entry_point();
  while (1) {
    printf("%s\n", *buf);
    yield(0);
  }
}

yielder* loop(int count) {
  entry_point();
  while ( count >= 0 )
    yield(count--);
  return_with_value(11);
  return yi_placeholder;
}

void receiveEnum(yielder* enumerator) {
  printf("Enum from function: %d\n", (int) next(enumerator));
}

int main()
{
    yielder* myLoop = loop(10);
    receiveEnum(myLoop);
    printf("Main enumerator next: %d\n", (int) next(myLoop));

    printf("Exiting ... :)\n");
    return 0;
}
