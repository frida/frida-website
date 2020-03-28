## Introduction

Stalker is FRIDA's code tracing engine. It allows threads to be followed,
capturing every function, every block, even every instruction which is executed.
A very good overview of the Stalker engine is provided
[here](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8) and we
recommend that you read it carefully first. Obviously, the implementation is
somewhat architecture specific, although there is much in common between them.
Stalker currently supports the AArch64 architecture commonly found on mobile
phones and tablets running Android or iOS, as well as the Intel 64 and IA-32
architectures commonly found on desktops and laptops. This page intends to take
things to the next level of detail, it dissects the ARM64 implementation of
Stalker and explains in more detail exactly how it works. It is hoped that this
may help future efforts to port Stalker to other hardware architectures.

## Disclaimer

Whilst this article will cover a lot of the details of the inner workings of
Stalker, it won't cover back-patching in real detail. It is intended as a
starting point to help others understand the technology and Stalker is
fiendishly complicated enough without this! To be fair though, this complexity
isn't there without reason, it is there to minimize the overhead of what is an
inherently expensive operation. Lastly, while this article will cover the key
concepts of the implementation and will extract some critical parts of the
implementation for a line-by-line analysis, there will be some last details of
the implementation left for the reader to discover by reading the [source
code](https://github.com/frida/frida-gum/blob/master/gum/backend-arm64/gumstalker-arm64.c).
However, it is hoped it will prove to be a very useful head-start.

## Use Cases

To start to understand the implementation of Stalker, we must first understand
in detail what it offers to the user. Whilst stalker can be invoked directly
through its native gum interface, most users will instead call it via the
[JavaScript API](https://frida.re/docs/javascript-api/#stalker) which will call
these gum methods on their behalf. The [typescript type
definitions](https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/frida-gum/index.d.ts)
for gum are well commented and provide a little more detail still.

The main API to Stalker from JavaScript is:

```
Stalker.follow([threadId, options])
```

> start stalking `threadId` (or the current thread if omitted)

Let's consider when these calls may be used. Stalking where you provide a thread
id is likely to be used where you have a thread of interest and are wondering
what it is doing. Perhaps it has an interesting name? Thread names can be found
using `cat /proc/PID/tasks/TID/comm`. Or perhaps you walked the threads in your
process using the FRIDA JavaScript API `Process.enumerateThreads()` and then
used a NativeFunction to call:

```
int pthread_getname_np(pthread_t thread,
                       char *name, size_t len);
```

Using this along with the
[Thread.backtrace](https://frida.re/docs/javascript-api/#thread) to dump thread
stacks can give you a really good overview of what a process is doing.

The other scenario where you might call `Stalker.follow` is perhaps from a
function which has been
[intercepted](https://frida.re/docs/javascript-api/#interceptor) or replaced. In
this scenario, you have found a function of interest and you want to understand
how it behaves, you want to see which functions or perhaps even code blocks the
thread takes after a given function is called. Perhaps you want to compare the
direction the code takes with different input, or perhaps you want to modify the
input to see if you can get the code to take a particular path.

In either of these scenarios, although Stalker has to work slightly differently
under the hood, it is all managed by the same simple API for the user,
`Stalker.follow`.

## Following

When the user calls `Stalker.follow`, under the hood, the javascript engine
calls through to either `gum_stalker_follow_me` to follow the current thread, or
`gum_stalker_follow(thread_id)` to follow another thread in the process.

### gum_stalker_follow_me

In the case of `gum_stalker_follow_me`, the Link Register is used to determine
the instruction at which to start stalking. In AARCH64 architecture, the Link
Register (LR) is set to the address of the instruction to continue execution
following the return from a function call, it is set to the address of the next
instruction by instructions such as BL and BLR. As there is only one link
register, if the called function is to call another routine, then the value of
LR must be stored (typically this will be on the stack). This value will
subsequently be loaded back from the stack into a register and the RET
instruction used to return control back to the caller.

Let's look at the code for `gum_stalker_follow_me`. This is the function
prototype:
```
GUM_API void gum_stalker_follow_me (GumStalker * self,
    GumStalkerTransformer * transformer, GumEventSink * sink);
```

So we can see the function is called by the v8 or duktape runtime passing 3
arguments. The first is a context of the Stalker object. Note that there may be
multiple of these if multiple threads are being stalked at once. The second is a
transformer, this can be used to transform the instrumented code as it is being
written (more on this later). The last parameter is the event sink, this is
where the generated events are passed as the stalker engine runs.

```
#ifdef __APPLE__
  .globl _gum_stalker_follow_me
_gum_stalker_follow_me:
#else
  .globl gum_stalker_follow_me
  .type gum_stalker_follow_me, %function
gum_stalker_follow_me:
#endif
  stp x29, x30, [sp, -16]!
  mov x29, sp
  mov x3, x30
#ifdef __APPLE__
  bl __gum_stalker_do_follow_me
#else
  bl _gum_stalker_do_follow_me
#endif
  ldp x29, x30, [sp], 16
  br x0
  ```

We can see that the first instruction STP stores a pair of registers onto the
stack. We can notice the expression `[sp, -16]!`. This is a
(pre-decrement)[https://thinkingeek.com/2017/05/29/exploring-aarch64-assembler-chapter-8/]
which means that the stack is advanced first by 16 bytes, then the two 8 byte
register values are stored. We can see the corresponding instruction `ldp x29,
x30, [sp], 16` at the bottom of the function. This is restoring these two
register values from the stack back into the registers. But what are these two
registers?

Well, `x30` is the Link register and `x29` is the Frame Pointer register. Recall
that we must store the link regsiter to the stack is we wish to call another
function as this will cause it to be overwritten and we need this value in order
that we can return to our caller.

The frame pointer is used to point to the top of the stack at the point a
function was called so that all the stack passed arguments and the stack based
local variables can be access at a fixed offset from the frame pointer. Again we
need to save and restore this as each function will have its value for this
register, so we need to store the value which our caller put in there and
restore it before we return. Indeed you can see in the next instruction `mov
x29, sp` that we set the frame pointer to the current stack pointer.

We can see the next instruction `mov x3, x30`, puts the value of the link
register into x3. The first 8 arguments on AARCH64 are passed in the registers
x0-x8. So this is being put into the register used for the fourth argument. We
then call (branch with link) the function `_gum_stalker_do_follow_me`. So we can
see that we pass the first three arguments in x0-x2 untouched, so that
`_gum_stalker_do_follow_me` receives the same values we were called with.
Finally, we can see after this function returns, we branch to the address we
receive as its return value. (In AARCH64 the return value of a function is
returned in x0).

```
gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           gpointer ret_addr)
```

### gum_stalker_follow

This routine has a very similar prototype to `gum_stalker_follow_me`, but has
the additional thread_id parameter. Indeed, if asked to follow the current
thread, then is will call that function. Let's look at the case when another
thread id is specified though.

```
void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumStalkerTransformer * transformer,
                    GumEventSink * sink)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_follow_me (self, transformer, sink);
  }
  else
  {
    GumInfectContext ctx;

    ctx.stalker = self;
    ctx.transformer = transformer;
    ctx.sink = sink;

    gum_process_modify_thread (thread_id, gum_stalker_infect, &ctx);
  }
}
```

We can see that this calls the function `gum_process_modify_thread`. This isn't
part of stalker, but part of gum itself. This function takes a callback with a
context parameter to call passing the thread context structure. This callback
can then modify the `GumCpuContext` structure and `gum_process_modify_thread`
will then write the changes back. We can see the context structure below, as you
can see it contains fields for all of the registers in the AARCH64 CPU. We can
also see below the function prototype of our callback.

```
typedef GumArm64CpuContext GumCpuContext;

struct _GumArm64CpuContext
{
  guint64 pc;
  guint64 sp;

  guint64 x[29];
  guint64 fp;
  guint64 lr;
  guint8 q[128];
};
```

```
static void
gum_stalker_infect (GumThreadId thread_id,
                    GumCpuContext * cpu_context,
                    gpointer user_data)
```

So, how does `gum_process_modify_thread` work? Well it depends on the platform.
On Linux (and Android) it uses the `ptrace` API (the same one used by GDB) to
attach to the thread and read and write registers. But there are a host of
complexities. On Linux, you cannot ptrace your own process (or indeed any in the
same process group), so FRIDA creates a clone of the current process in its own
process group and shares the same memory space. It communicates with it using a
UNIX socket. This cloned process acts as a debugger, reading the registers of
the original target process and storing them in the shared memory space and then
writing them back to the process on demand. Oh and then there is
`PR_SET_DUMPABLE` and `PR_SET_PTRACER` which control the permissions of who is
allowed to ptrace our original process.

Now you will see that the functionality of `gum_stalker_infect` is actually
quite similar to that of `_gum_stalker_do_follow_me` we mentioned earlier. Both
function carry out essentially the same job, although
`_gum_stalker_do_follow_me` is running on the target thread, but
`gum_stalker_infect` is not, so it must write some code to be called by the
target thread using the
[gum_arm64_writer](https://github.com/frida/frida-gum/blob/master/gum/arch-arm64/gumarm64writer.c)
rather than calling functions directly.

We will cover these functions in more detail shortly, but first we need a little
more background.

## Basic Operation

Code can be thought of as a series of blocks of instructions (also known as
basic blocks). Each block starts with an optional series of instructions (we may
have two consecutive branch statements) which run in sequence and ends when we
encounter an instruction which causes (or can cause) execution to continue with
an instruction other than the one immediately following it in memory.

Stalker works on one block at a time. It starts with either the block after the
return to the call to `gum_stalker_follow_me` or the block of code to which the
instruction pointer of the target thread is pointing when `gum_stalker_follow`
is called.

Stalker works by allocating some memory and writing to it a new instrumented
copy of the original block. Instructions may be added to generate events, or
carry out any of the other features the stalker engine offers. Stalker must also
relocate instructions as necessary. Consider the following instruction:

```
ADR
Address of label at a PC-relative offset.

ADR  Xd, label

Xd
Is the 64-bit name of the general-purpose destination
register, in the range 0 to 31.

label
Is the program label whose address is to be calculated.
It is an offset from the address of this instruction,
in the range ±1MB.
```

If this instruction is copied to a different location in memory and executed,
then because the address of the label is calculated by adding an offset to the
current instruction pointer, then the value would be different. Fortunately, gum
has a
[relocator](https://github.com/frida/frida-gum/blob/76b583fb2cd30628802a6e0ca8599858431ee717/gum/arch-arm64/gumarm64relocator.c)
for just this purpose which is capable of modifying the instruction given its
new location so that the correct address is calculated.

Now, recall we said that Stalker works one block at a time. How, then do we
instrument the next block? We remember also that each block also ends with a
branch instruction, well if we modify this branch to instead branch back into
the Stalker engine, but ensure we store the destination of where the branch was
intending to end up, we can instrument the next block and re-direct execution
there instead. This same simple process can continue with one block after the
next.

Now, this process can be a little slow, so there are a few optimizations which
we can apply. First of all, if we execute the same block of code more than once
(e.g a loop, or maybe just a function called multiple times) we don't have to
re-instrument it all over again. We can just re-execute the same instrumented
code. For this reason, a hashtable is kept of all of the blocks which we have
encountered before and where we put the instrumented copy of the block.

Secondly, we can instrument blocks ahead of time. For example, if we encounter a
call instruction, it is pretty likely (unless it throws an exception) that the
callee will eventually return and block immediately following the call will be
executed. So we can instrument this block at the same time we instrument the
block which is being called. Whilst we may still return into stalker following
the call before we are re-directed to the already instrumented block, we may not
need to store quite so much of the CPU state when entering and exiting the
engine and so may some time. This doesn't work for all branches, however, many
branches may never be taken. Consider all the error handling code in a normal
program. Assuming the input is valid none of it will run, or the first problem
with the input will be detected and only that error handler will run. So if we
were to instrument both paths of every branch instruction, we would end un
instrumenting a lot of code which is never run. This would take up valuable time
and memory.

Finally, if a block of code ends with a deterministic branch (e.g. the
destination is fixed and the branch is not conditional) then rather than
replacing that last branch with a call back to Stalker to instrument the next
block, we can instrument the next block ahead of time and direct control flow
there without having to re-enter the stalker engine. This process is called
backpatching. In actual fact, we can deal with conditional branches too, if we
instrument both blocks of code (the one if the branch is taken and the one if it
isn't) then we can replace the original conditional branch with one conditional
branch which directs control flow to instrumented version of the block
encountered when the branch was taken, followed by a unconditional branch to the
other instrumented block. We can also deal partially with branches where the
target is not static. Say our branch is something like:

```
BR x0
```

This sort of instruction is common when calling a function pointer, or class
method. Whilst the value of x0 can change, quite often it will actually always
be the same. In this case, we can replace the final branch instruction with code
which compares the value of x0 against our known function, and if it matches
branches to the address of the instrumented copy of the code. This can then be
followed by an unconditional branch back to the Stalker engine if it doesn't
match. So if the value of the function pointer say is changed, then the code
will still work and we will re-enter Stalker and instrument wherever we end up.
However, if as we expect it remains unchanged then we can bypass the Stalker
engine altogether and go straight to the instrumented function.

## Options

Now let's look at the options when we follow a thread with Stalker. Stalker
generates events when a followed thread is being executed, these are placed onto
a queue and flushed either periodically or manually by the user. The size and
time period can be configured by the options. Events can be generated on a
per-instruction basis either for calls, returns or all instructions. Or they can
be generated on a block basis, either when a block is executed, or when it is
instrumented by the Stalker engine.

We can also provide one of two callbacks `onReceive` or `onCallSummary`. The
former will quite simply deliver a binary blob containing the raw events
generated by Stalker, with events in the order that they were generated in.
(`Stalker.parse()` can be used to turn it into a JS array of tuples representing
the events.). The second aggregates these results simply returning a count of
times each function was called. This is more efficient than `onReceive`, but the
data is much less granular.

## Terminology

Before we can carry on with describing the detailed implementation of stalker,
we first need to understand some key terminology and concepts that are used in
the design.

### Probes

Whilst a thread is running outside of stalker, you may be familiar with using
`Interceptor.attach()` to get a callback when a given function is called. When a
thread is running in stalker, however, these interceptors may not work. These
interceptors work by patching the first few instructions (prologue) of the
target function to re-direct execution into FRIDA. Frida copies and relocates
these first few instructions somewhere else so that after the `onEnter` callback
has been completed, it can re-direct control flow back to the original function.

The reasons these may not work within stalker is simple, the original function is
never called. Each block, before it is executed is instrumented elsewhere in
memory and it is this copy which is executed. Stalker supports the API function
`Stalker.addCallProbe(address, callback[, data])` to provide this functionality
instead. The optional data parameter is passed when the probe callback is
registered and will be passed to the callback routine when executed. This
pointer, therefore needs to be stored in the stalker engine. Also the address
needs to be stored, so that when an instruction is encountered which calls the
function, the code can instead be instrumented to call the function first. As
multiple functions may call the one to which you add the probe, many
instrumented blocks may contain additional instructions to call the probe
function. Thus whenever a probe is added or removed, the cached instrumented
blocks are all destroyed and so all code has to be re-instrumented.

### Trust Threshold

Recall that one of the simple optimizations we apply is that if we attempt to
execute a block more than once, on subsequent occasions, we can simply call the
instrumented block we created last time around? Well, that only works if the
code we are instrumenting hasn't changed. In the case of self-modifying code
(which is quite often used as an anti-debugging/anti-disassembly technique to
attempt to frustrate analysis of security critical code) the code may change,
and hence the instrumented block cannot be re-used. So, how do we detect if a
block has changed? We simply keep a copy of the original code in the
data-structure along with the instrumented version. Then when we encounter a
block again, we can compare the code we are going to instrument with the version
we instrumented last time and if they match, we can re-use the block. But
performing the comparison every time a block runs may slow things down. So
again, this is an area where stalker can be customized.

> `Stalker.trustThreshold`: an integer specifying how many times a piece of code
> needs to be executed before it is assumed it can be trusted to not mutate.
> Specify -1 for no trust (slow), 0 to trust code from the get-go, and N to
> trust code after it has been executed N times. Defaults to 1.

In actual fact, the value of N is the number of times the block needs to be
re-executed and match the previously instrumented block (e.g. be unchanged)
before we stop performing the comparison. Note that the original copy of the
code block is still stored even when the trust threshold is set to `-1` or `0`.
Whilst it is not actually needed for these values, it has been
retained to keep things simple.
In any case, neither of these is
the default setting.

### Excluded Ranges

Stalker also has the API `Stalker.exclude(range)` that's passed a base and limit
used to prevent Stalker from instrumenting code within these regions.
Consider, for example, your thread calls `malloc()` inside `libc`. You most
likely don't care about the inner workings of the heap and this is not only
going to slow down performance, but also generate a whole lot of extraneous
events you don't care about. One thing to consider, however, is that as soon as
a call is made to an excluded range, stalking of that thread is stopped until it
returns. That means, if that thread were to call a function which is not inside
a restricted range, a callback perhaps, then this would not be captured by
stalker. Just as this can be used to stop the stalking of a whole library, it can
be used to stop stalking a given function (and its callees) too. This can be
particularly useful if your target application is statically linked. Here, was
cannot simply ignore all calls to `libc`, but we can find the symbol for
`malloc()` using `Module.enumerateSymbols()` and ignore that single function.

### Freeze/Thaw

As an extension to DEP, some systems prevent pages from being marked writable
and executable at the same time. Thus FRIDA must toggle the page permissions
between writable and executable to write instrumented code, and allow that code
to execute respectively. When pages are executable, they are said to be frozen
(as they cannot be changed) and when they are made writeable again, they are
considered thawed.

### Call Instructions

AArch64, unlike Intel doesn't have an single explicit `call` instruction, which
has different forms to cope with all supported scenarios. Instead, it uses a
number of different instructions to offer support for function calls. These
instructions all branch to a given location and update the Link register, `LR`,
with the return address:

* `BL`
* `BLR`
* `BLRAA`
* `BLRAAZ`
* `BLRAB`
* `BLRABZ`

For simplicity, in the remainder of this article, we will refer to this
collection of instructions as “call instructions”.

### Frames

Whenever stalker encounters a call, it stores the return address and the address
of the instrumented return block forwarder in a structure and adds these to a stack stored
in a data-structure of its own. It uses this as a speculative optimization, and also as a heuristic to approximate the call depth when emitting call and return events.

```
typedef struct _GumExecFrame GumExecFrame;

struct _GumExecFrame
{
  gpointer real_address;
  gpointer code_address;
};
```

### Transformer

A `GumStalkerTransformer` type is used to generate the instrumented code. The
implementation of the default transformer looks like this:

```
static void
gum_default_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerWriter * output)
{
  while (gum_stalker_iterator_next (iterator, NULL))
  {
    gum_stalker_iterator_keep (iterator);
  }
}
```

It is called by the function responsible for generating instrumented code,
`gum_exec_ctx_obtain_block_for()` and its job is to generate the instrumented
code. We can see that it does this using a loop to process one instruction at a
time. First retrieving an instruction from the iterator, then telling stalker to
instrument the instruction as is (without modification). These two functions are
implemented inside stalker itself. The first is responsible for parsing a
`cs_insn` and updating the internal state. This `cs_insn` type is a datatype
used by the internal [Capstone](http://www.capstone-engine.org/) disassembler to
represent an instruction. The second is responsible for writing out the
instrumented instruction (or set of instructions). We will cover these in more
detail later.

Rather than using the default transformer, the user can instead provide a custom
implementation which can replace and insert instructions at will. A good example
is provided in the [API
documentation](https://frida.re/docs/javascript-api/#stalker).

### Callouts

Transformers can also make callouts. That is they instruct stalker to emit
instructions to make a call to a JavaScript (or CModule) function passing the
CPU context and an optional context parameter. This function is then able to
modify or inspect registers at will. This information is stored in a
```GumCallOutEntry```.

```
typedef void (* GumStalkerCallout) (GumCpuContext * cpu_context,
    gpointer user_data);

typedef struct _GumCalloutEntry GumCalloutEntry;

struct _GumCalloutEntry
{
  GumStalkerCallout callout;
  gpointer data;
  GDestroyNotify data_destroy;

  gpointer pc;

  GumExecCtx * exec_context;
};
```

### EOB/EOI

Recall that the
[Relocator](https://github.com/frida/frida-gum/blob/master/gum/arch-arm64/gumarm64relocator.c)
is heavily involved in generating the instrumented code. It has two important
properties which control its state.

End of Block (EOB) indicates that the end of a block has been reached. This
occurs when we encounter *any* branch instruction. A branch, a call, or a return
instruction.

End of Input (EOI) indicates that not only have we reached the end of a block,
but we have possibly reached the end of the input, i.e. what follows this
instruction may not be another instruction. Whilst this is not the case for a
call instruction as code control will (typically) pass back when the callee returns and so
more instructions must follow (note that a compiler will typically generate a
branch instruction for a call to a non-returning function like `exit()`), if we
encounter a branch instruction, or a return instruction, we have no guarantee
that code will follow afterwards.

### Prologues/Epilogues

When control flow is redirected from the program into the stalker engine, the
registers of the CPU must be saved so that stalker can run and make use of the
registers and restore them before control is passed back to the program so that
no state is lost.

The [Procedure Call
Standard](https://static.docs.arm.com/den0024/a/DEN0024A_v8_architecture_PG.pdf)
for AArch64 states that some registers (notably x19 to x29) are callee saved
registers. This means that when the compiler generates code which makes use of
these registers, it must store them first. Hence it is not strictly necessary to
save these registers to the context structure, since they will be restored if
they are used by the code within the stalker engine. This *"minimal"* context is
sufficient for most purposes.

However, if the Stalker engine is to call a probe registered by
`Stalker.addCallProbe()`, or a callout created by `iterator.putCallout()` (called by
a Transformer), then these callbacks will expect to receive the full CPU context
as an argument. And they will expect to be able to modify this context and for
the changes to take effect when control is passed back to the application code.
Thus for these instances, we must write a *"full"* context and its layout must
match the expected format dictated by the structure `GumArm64CpuContext`.

```
typedef struct _GumArm64CpuContext GumArm64CpuContext;

struct _GumArm64CpuContext
{
  guint64 pc;
  guint64 sp; /* x31 */
  guint64 x[29];
  guint64 fp; /* x29 - frame pointer */
  guint64 lr; /* x30 */
  guint8 q[128]; /* FPU, NEON (SIMD), CRYPTO regs */
};
```

Note however, that the code necessary to write out the necessary CPU registers
(the prologue) in either case is quite long (tens of instructions). And the code
to restore them afterwards (the epilogue) is similar in length. We don't want to
write these at the beginning and end of every block we instrument. Therefore we
write these (in the same way we write the instrumented blocks) into a common
memory location and simply emit call instructions at the beginning and end of
each instrumented block to call these functions. These common memory locations
are referred to as *helpers*. The following functions create these prologues and
epilogues.

```
static void gum_exec_ctx_write_minimal_prolog_helper (
    GumExecCtx * ctx, GumArm64Writer * cw);

static void gum_exec_ctx_write_minimal_epilog_helper (
    GumExecCtx * ctx, GumArm64Writer * cw);

static void gum_exec_ctx_write_full_prolog_helper (
    GumExecCtx * ctx, GumArm64Writer * cw);

static void gum_exec_ctx_write_full_epilog_helper (
    GumExecCtx * ctx, GumArm64Writer * cw);
```

Finally, note that in AArch64 architecture, it is only possible to make a direct
branch to code within ±128 MB of the caller, and using an
indirect branch is more expensive (both in terms of code size and performance).
Therefore, as we write more and more instrumented blocks, we will get further
and further away from the shared prologue and epilogue. If we get more than
128 MB away, we simply write out another copy of these prologues and epilogues to
use. This gives us a very reasonable tradeoff.

### Counters

Finally, there are a series of counters which you can see kept recording the
number of each type of instructions encountered at the end of an instrumented
block. These are only used by the test-suite to guide the developer during
performance tuning, indicating which branch types most commonly require
a full context-switch into Stalker to resolve the target.

## Slabs

Let's now take a look at where stalker stores its instrumented code, in slabs.
Below are the data-structures used to hold it all:

```
typedef guint8 GumExecBlockFlags;
typedef struct _GumExecBlock GumExecBlock;
typedef struct _GumSlab GumSlab;

struct _GumExecBlock
{
  GumExecCtx * ctx;
  GumSlab * slab;

  guint8 * real_begin;
  guint8 * real_end;
  guint8 * real_snapshot;
  guint8 * code_begin;
  guint8 * code_end;

  GumExecBlockFlags flags;
  gint recycle_count;
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  GumSlab * next;

  guint num_blocks;
  GumExecBlock blocks[];
};

enum _GumExecBlockFlags
{
  GUM_EXEC_ACTIVATION_TARGET = (1 << 0),
};
```

Now let's look at some code when stalker is initialized which configures their
size:

```
#define GUM_CODE_SLAB_MAX_SIZE  (4 * 1024 * 1024)
#define GUM_EXEC_BLOCK_MIN_SIZE 1024

static void
gum_stalker_init (GumStalker * self)
{
  ...

  self->page_size = gum_query_page_size ();
  self->slab_size =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_MAX_SIZE, self->page_size);
  self->slab_header_size =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_MAX_SIZE / 12, self->page_size);
  self->slab_max_blocks = (self->slab_header_size -
      G_STRUCT_OFFSET (GumSlab, blocks)) / sizeof (GumExecBlock);

  ...
}
```

So we can see that each slab is 4 MB in size. A 12th of this slab is reserved for
its header, the `GumSlab` structure itself including its `GumExecBlock` array.
Note that this is defined as a zero length array at the end of the `GumSlab`
structure, but the actual number of these which can fit in the header of the
slab is calculated and stored in `slab_max_blocks`.

So what is the remainder of the slab used for? Whilst the header of the slab is
used for all the accounting information, the remainder (henceforth referred to
as the tail) of the slab is used for the instrumented instructions themselves
(they are stored inline in the slab).

So why is a 12th of the slab allocated for the header and the remainder for the
instructions? Well the length of each block to be instrumented will vary
considerably and may be affected by the compiler being used and its optimization
settings. Some rough empirical testing showed that given the average length of
each block this might be a reasonable ratio to ensure we didn't run out of space for new
`GumExecBlock` entries before we ran out of space for new instrumented blocks in
the tail and vice versa.

Let's now look at the code which creates them:

```
static GumSlab *
gum_exec_ctx_add_slab (GumExecCtx * ctx)
{
  GumSlab * slab;
  GumStalker * stalker = ctx->stalker;

  slab = gum_memory_allocate (NULL, stalker->slab_size,
      stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  slab->data = (guint8 *) slab + stalker->slab_header_size;
  slab->offset = 0;
  slab->size = stalker->slab_size - stalker->slab_header_size;
  slab->next = ctx->code_slab;

  slab->num_blocks = 0;

  ctx->code_slab = slab;

  return slab;
}
Here, we can see that the `data` field points to the start of the tail where
instructions can be written after the header. The `offset` field keeps track of our
offset into the tail. The `size` field keeps track of the total number of bytes
available in the tail. The `num_blocks` field keeps track of how many
instrumented blocks have been written to the slab.

Note that where possible we allocate the slab with RWX permissions so that we
don't have to freeze and thaw it all of the time. On systems which support RWX
the freeze and thaw functions become no-ops.

Lastly, we can see that each slab contains a `next` pointer which can be used to
link slabs together to form a singly-linked list. This is used so we can walk
them and dispose them all when stalker is finished.

## Blocks

Now we understand how the slabs work. Let's look in more detail at the blocks.
As we know, we can store multiple blocks in a slab and write their instructions
to the tail. Let's look at the code to allocate a new block:

```
static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumSlab * slab = ctx->code_slab;
  gsize available;

  available = (slab != NULL) ? slab->size - slab->offset : 0;
  if (available >= GUM_EXEC_BLOCK_MIN_SIZE &&
      slab->num_blocks != stalker->slab_max_blocks)
  {
    GumExecBlock * block = slab->blocks + slab->num_blocks;

    block->ctx = ctx;
    block->slab = slab;

    block->code_begin = slab->data + slab->offset;
    block->code_end = block->code_begin;

    block->flags = 0;
    block->recycle_count = 0;

    gum_stalker_thaw (stalker, block->code_begin, available);
    slab->num_blocks++;

    return block;
  }

  if (stalker->trust_threshold < 0 && slab != NULL)
  {
    slab->offset = 0;

    return gum_exec_block_new (ctx);
  }

  gum_exec_ctx_add_slab (ctx);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

  return gum_exec_block_new (ctx);
}
The function first checks if there is space for a minimally sized block in the
tail of the slab (1024 bytes) and whether there is space in the array of
`GumExecBlocks` in the slab header for a new entry. If it does then a new entry
is created in the array and its pointers are set to reference the `GumExecCtx` (the
main stalker session context) and the `GumSlab`, The `code_begin` and `code_end`
pointers are both set to the first free byte in the tail. The `recycle_count`
used by the trust threshold mechanism to determine how many times the block has
been encountered unmodified is reset to zero, and the remainder of the tail is
thawed to allow code to be written to it.

Next if the trust threshold is set to less than zero (recall -1 means blocks are
never trusted and always re-written) then we reset the slab `offset` (the
pointer to the first free byte in the tail) and start over. This means that any
instrumented code written for any blocks within the slab will be overwritten.

Finally, as there is no space left in the current slab and we can't overwrite it
because the trust threshold means blocks may be re-used, then we must allocate a
new slab by calling `gum_exec_ctx_add_slab()`, which we looked at above. We
then call `gum_exec_ctx_ensure_inline_helpers_reachable()`, more on that in a
moment, and then we allocate our block from the new slab.

Recall, that we use *helpers* (such as the prologues and epilogues that save and
restore the CPU context) to prevent having to duplicate these instructions at
the beginning and end of every block. As we need to be able to call these from
instrumented code we are writing to the slab, and we do so with a direct branch
that can only reach ±128 MB from the call site, we need to ensure we can get to
them. If we haven't written them before, then we write them to our current slab.
Note that these helper funtions need to be reachable from any instrumented
instruction written in the tail of the slab. Because our slab is only 4 MB in
size, then if our helpers are written in our current slab then they will be
reachable just fine. If we are allocating a subsequent slab and it is close
enough to the previous slab (we only retain the location we last wrote the
helper functions to) then we might not need to write them out again and can just
rely upon the previous copy in the nearby slab. Note that we are at the mercy of
`mmap()` for where our slab is allocated in virtual memory and ASLR may dictate
that our slab ends up nowhere near the previous one.

We can only assume that either this is unlikely to be a problem, or that this
has been factored into the size of the slabs to ensure that writing the helpers
to each slab isn't much of an overhead because it doesn't use a significant
proportion of their space. An alternative could be to store every location
every time we have written out a helper function so that we have more candidates
to choose from (maybe our slab isn't allocated nearby the one previously
allocated, but perhaps it is close enough to one of the others). Otherwise, we
could consider making a custom allocator using `mmap()` to reserve a large (e.g.
128 MB) region of virtual address space and then use `mmap()` again to commit the
memory one slab at a time as needed. But these ideas are perhaps both overkill.

## Instrumenting Blocks

The main function which instruments a code block is called
`gum_exec_ctx_obtain_block_for()`. It first looks for an existing block in the
hash table which is indexed on the address of the original block which was
instrumented. If it finds one and the aforementioned constraints around the
trust threshold are met then it can simply be returned.

The fields of the `GumExecBlock` are used as follows. The `real_begin` is set to
the start of the original block of code to be instrumented. The `code_begin`
field points to the first free byte of the tail (remember this was set by the
`gum_exec_block_new()` function discussed above). A `GumArm64Relocator` is
initialized to read code from the original code at `real_begin` and a
`GumArm64Writer` is initialized to write its output to the slab starting at
`code_begin`. Each of these items is packaged into a `GumGeneratorContext` and
finally this is used to construct a `GumStalkerIterator`.

This iterator is then passed to the transformer. Recall the default
implementations is as follows:

```
static void
gum_default_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerWriter * output)
{
  while (gum_stalker_iterator_next (iterator, NULL))
  {
    gum_stalker_iterator_keep (iterator);
  }
}
```

We will gloss over the details of `gum_stalker_iterator_next()` and
`gum_stalker_iterator_keep()` for now. But in essence, this causes the iterator to
read code one instruction at a time from the relocator, and write the relocated
instruction out using the writer. Following this process, the `GumExecBlock`
structure can be updated. It's field `real_end` can be set to the address where
the relocator read up to, and its field `code_end` can be set to the address
which the writer wrote up to. Thus `real_begin` and `real_end` mark the limits
of the original block, and `code_begin` and `code_end` mark the limits of the
newly instrumented block. Finally, `gum_exec_ctx_obtain_block_for()` calls
`gum_exec_block_commit()` which takes a copy of the original block and places it
immediately after the instrumented copy. The field `real_snapshot` points to
this (and is thus identical to `code_end`). Next the slab's `offset` field is
updated to reflect the space used by our instrumented block and our copy of the
original code. Finally, the block is frozen to allow it to be executed.

```
static void
gum_exec_block_commit (GumExecBlock * block)
{
  gsize code_size, real_size;

  code_size = block->code_end - block->code_begin;
  block->slab->offset += code_size;

  real_size = block->real_end - block->real_begin;
  block->real_snapshot = block->code_end;
  memcpy (block->real_snapshot, block->real_begin, real_size);
  block->slab->offset += real_size;

  gum_stalker_freeze (block->ctx->stalker, block->code_begin,
      code_size);
}
```

Now let's just return to a few more details of the function
`gum_exec_ctx_obtain_block_for()`. First we should note that each block has a
single instruction prefixed.

```
gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
    ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
    GUM_INDEX_POST_ADJUST);
This instruction is the restoration prolog (denoted by
`GUM_RESTORATION_PROLOG_SIZE`). This is skipped in “bootstrap” usage – hence you will
note this constant is added on by `_gum_stalker_do_follow_me()` and
`gum_stalker_infect()` when returning the address of the instrumented code. When
return instructions are instrumented, however, if the return is to a block which
has already been instrumented, then we can simply return to that block rather
than returning back into the stalker engine. This requires a couple of registers
to be used in the generated assembly to figure out though and this means they
have to be stored on the stack (written by
`gum_exec_block_write_ret_transfer_code()`). In the event that we can return
directly to an instrumented block, we return to this first instruction which
restores these registers from the stack. This will be covered in more detail
later.

Secondly, we can see `gum_exec_ctx_obtain_block_for()` does the
following after the instrumented block is written:
```
gum_arm64_writer_put_brk_imm (cw, 14);
```

This inserts a break instruction which is intended to simplify debugging.

Lastly, if stalker is configured to, `gum_exec_ctx_obtain_block_for()` will
generate an event of type `GUM_COMPILE` when compiling the block.

## Helpers

We can see from `gum_exec_ctx_ensure_inline_helpers_reachable()` that
we have a total of 6 helpers. These helpers are common fragments of code which
are needed repeatedly by our instrumented blocks. Rather than emitting the code
they contain repeatedly, we instead write it once and place a call or branch
instruction to have our instrumented code execute it. Recall that the helpers
are written into the same slabs we are writing our instrumented code into and
that if possible we can re-use the helper written into a previous nearby slab
rather than putting a copy in each one.

This function calls `gum_exec_ctx_ensure_helper_reachable()` for each helper which
in turn calls `gum_exec_ctx_is_helper_reachable()` to check if the helper is
within range, or otherwise calls the callback passed as the second argument to
write out a new copy.

```
static void
gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx)
{
  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_prolog_minimal,
      gum_exec_ctx_write_minimal_prolog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_epilog_minimal,
      gum_exec_ctx_write_minimal_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_prolog_full,
      gum_exec_ctx_write_full_prolog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_epilog_full,
      gum_exec_ctx_write_full_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_stack_push,
      gum_exec_ctx_write_stack_push_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_stack_pop_and_go,
      gum_exec_ctx_write_stack_pop_and_go_helper);
}
```

So, what are our 6 helpers. We have 2 for writing prologues which store register
context, one for a full context and one for a minimal context. We will cover
these later. We also have 2 for their corresponding epilogues for restoring the
registers. The other two, the `last_stack_push` and `last_stack_pop_and_go` are
used when instrumenting call instructions.

Before we analyze these two in detail, we first need to understand the frame
structures. We can see from the code snippets below that we allocate a page to
contain `GumExecFrame` structures. These structures are stored sequentially in
the page like an array and are populated starting with the entry at the end of
the page. Each frame contains the address of the original block and the address
of the instrumented block which we generated to replace it:

```
typedef struct _GumExecFrame GumExecFrame;
typedef struct _GumExecCtx GumExecCtx;

struct _GumExecFrame
{
  gpointer real_address;
  gpointer code_address;
};

struct _GumExecCtx
{
  ...
  GumExecFrame * current_frame;
  GumExecFrame * first_frame;
  GumExecFrame * frames;
  ...
};

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumThreadId thread_id,
                             GumStalkerTransformer * transformer,
                             GumEventSink * sink)
{
  ...

  ctx->frames = gum_memory_allocate (
      NULL, self->page_size, self->page_size, GUM_PAGE_RW);
  ctx->first_frame = (GumExecFrame *) ((guint8 *) ctx->frames +
      self->page_size - sizeof (GumExecFrame));
  ctx->current_frame = ctx->first_frame;

  ...

  return ctx;
}
```

### last_stack_push

Much of the complexity in understanding Stalker and the helpers in particular is
that some functions – let's call them writers – write code which is executed at a
later point. These writers have branches in themselves which determine exactly
what code to write, and the written code can also sometimes have branches too. The
approach I will take for these two helpers therefore is to show pseudo code for
the assembly which is emitted into the slab which will be called by instrumented
blocks.

The pseudo code for this helper is shown below:

```
void last_stack_push_helper(gpointer x0, gpointer x1) {
  GumExecFrame** x16 = &ctx->current_frame
  GumExecFrame* x17 = *x16
  void* x2 = x17 & (ctx->stalker->page_size - 1)
  if x2 != 0:
    x17--
    x17.real_address = x0
    x17.code_address = x1
    *x16 = x17
  return
}
```
As we can see, this helper is actually a simple function which takes two
arguments, the `real_address` and the `code_address` to store in the next
`GumExecFrame` structure. Note that our stack is written backwards from the end
of the page in which they are stored towards the start and that `current_frame`
points to the last used entry (so our stack is full and descending). Also note
we have a conditional check to see whether we are on the last entry (the one at
the very beginning of the page will be page-aligned) and if we have run out of
space for more entries (we have space for 512) then we simply do nothing. If we
have space, we write the values from the parameters into the entry and retard
the `current_frame` pointer to point to it.

This helper is used when *virtualizing* call instructions. Virtualizing is the
name given to the replacement of an instruction typically those relating to
branching with a series of instructions which instead of executing the intended
block allow stalker to manage the control-flow. Recall as our transformer walks
the instructions using the iterator and calls `iterator.keep()` we output our
transformed instruction. When we encounter a branch, we need to emit code to
call back into the Stalker engine so that it can instrument that block, but if
the branch statement is a call instruction (`BL`, `BLX` etc) we also need to
emit a call to the above helper to store the stack frame information. This
information is used when emitting call events as well as later when optimizing
the return.

### last_stack_pop_and_go

Now lets look at the `last_stack_pop_and_go` helper. To understand this, we also
need to understand the code written by `gum_exec_block_write_ret_transfer_code()`
(the code that calls it), as well as that written by
`gum_exec_block_write_exec_generated_code()` which it calls. We will skip over
pointer authentication for now.

```
void ret_transfer_code(arm64_reg ret_reg) {
  gpointer x16 = ret_reg
  goto last_stack_pop_and_go_helper
}

void last_stack_pop_and_go_helper(gpointer x16) {
  GumExecFrame** x0 = &ctx->current_frame
  GumExecFrame* x1 = *x0
  gpointer x17 = x0.real_address
  if x17 == x16:
    x17 = x0.code_address
    x1++
    *x0 = x1
    goto x17
  else:
    x1 = ctx->first_frame
    *x0 = x1
    gpointer* x0 = &ctx->return_at
    *x0 = x16
    last_prologue_minimal()
    x0 = &ctx->return_at
    x1 = *x0
    gum_exec_ctx_replace_current_block_from_ret(ctx, x1)
    last_epilogue_minimal()
    goto exec_generated_code
}

void exec_generated_code() {
  gpointer *x16 = &ctx->resume_at
  gpointer x17 = *x16
  goto x17
}
```

So this code is a little harder. It isn't really a function and the actual
assembly written by it is muddied a little by the need to save and restore
registers. But the essence of it is this: When virtualizing a return instruction
this helper is used to optimize passing control back to the caller. ret_reg
contains the address of the block to which we are intending to return.

Lets take a look at the definition of the return instruction:
```
RET
Return from subroutine, branches unconditionally to an address
in a register, with a hint that this is a subroutine return.

RET  {Xn}
Where:

Xn
Is the 64-bit name of the general-purpose register holding the
address to be branched to, in the range 0 to 31. Defaults to
X30 if absent.
```

As we can see, we are going to return to an address passed in a register.
Typically, we can predict the register value and where we will return to, as the
compiler will emit assembly code so that the register is set to the address of
the instruction immediately following the call which got us there. As we
instrument the block following a call instruction when we encounter the call,
and we store the addresses of both the original block following the call and its
instrumented copy in the `GumExecFrame` structure we can simply virtualize our
return instruction by replacing it with instructions which simply branch to the
instrumented block. We don't need to re-enter the stalker engine each time we
see a return instruction and get a nice performance boost. Simple!

However, remember that the user can use a custom transform to modify
instructions as they see fit, they can insert instructions which modify register
values, or perhaps a callout function which is passed the context structure
which allows them to modify register values as they like. Now consider what if
they modify the value in the return register!

So we can see that the helper checks the value of the return register against
the value of the `real_address` stored in the stack frame. If it matches, then
all is well and we can simply branch directly to the already instrumented block.
Otherwise, we follow a different path. First the array of `GumExecFrame` is
cleared, now our control-flow has deviated, we will start again building our
stack again. We accept that we will take this same slower path for any previous
frames in the call-stack we recorded so far if we ever return to them, but will
have the possibility of using the fast path for new calls we encounter from here
on out (until the next time a call instruction is used in an unconventional manner).

We make a minimal prologue (our instrumented code is now going to have to
re-enter stalker) and we need to be able to restore the application's registers
before we return control back to it. We call the entry gate for return,
`gum_exec_ctx_replace_current_block_from_ret()` (more on entry gates later). We
then execute the corresponding epilogue before branching to the
`ctx->resume_at` pointer which is set by stalker during the above call to
`gum_exec_ctx_replace_current_block_from_ret()` to point to the new instrumented
block.

## Context

Let's look at the prologues and epilogues now.

```c
static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_prolog_minimal
      : ctx->last_prolog_full;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_LR, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_epilog_minimal
      : ctx->last_epilog_full;

  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_X20, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
}
```

We can see that these do little other than call the corresponding prologue or
epilogue helpers. We can see that the prologue will store `x19` and the link
register onto the stack. These are then restored into `x19` and `x20` at the end
of the epilogue.  This is because `x19` is needed as scratch space to write the
context blocks and the link register needs to be preserved as it will be
clobbered by the call to the helper.

The LDP and STP instructions load and store a pair of registers respectively and
have the option to increment or decrement the stack pointer. This increment or
decrement can be carried out either before, or after the values are loaded or
stored.

Note also the offset at which these registers are placed. They are stored at
`16` bytes + `GUM_RED_ZONE_SIZE` beyond the top of the stack. Note that our
stack on AArch64 is full and descending. This means that the stack grows toward
lower addresses and the stack pointer points to the last item pushed (not to the
next empty space). So, if we subtract 16 bytes from the stack pointer, then this
gives us enough space to store the two 64-bit registers. Note that the stack
pointer must be decremented before the store (pre-decrement) and incremented
after the load (post-increment).

So what is `GUM_RED_ZONE_SIZE`? The
[redzone](http://hungri-yeti.com/2015/10/19/the-arm64-aarch64-stack/) is a 128
byte area beyond the stack pointer which a function can use to store temporary
variables. This allows a function to store data in the stack without the need to
adjust the stack pointer all of the time. Note that this call to the prologue is
likely the first thing to be carried out in our instrumented block, we don't
know what local variables the application code has stored in the redzone and so
we must ensure that we advance the stackpointer beyond it before we start using
the stack to store information for the stalker engine.

## Context Helpers

Now that we have looked at how these helpers are called, let us now have a look at
the helpers themselves. Although there are two prologues and two epilogues (full
and minimal), they are both written by the same function as they have much in
common. The version which is written is based on the function parameters. The
easiest way to present these is with annotated code:

```
static void
gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  // Keep track of how much we are pushing onto the stack since we
  // will want to store in the exec context where the original app
  // stack was. At present the call to our helper already skipped
  // the red zone and stored LR and X19.
  gint immediate_for_sp = 16 + GUM_RED_ZONE_SIZE;

  // This instruction is used to store the CPU flags into x15.
  const guint32 mrs_x15_nzcv = 0xd53b420f;

  // Note that only the full prolog has to look like the C struct
  // definition, since this is the data structure passed to
  // callouts and the like.

  // Save Return address to our instrumented block in X19. We will
  // preserve this throughout and branch back there at the end.
  // This will take us back to the code written by
  // gum_exec_ctx_write_prolog()
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);

  // LR = SP[8] Save return address of previous block (or user-code)
  // in LR. This was pushed there by the code written by
  // gum_exec_ctx_write_prolog(). This is the one which will remain in
  // LR once we have returned to our instrumented code block. Note
  // the use of SP+8 is a little asymmetric on entry (prolog) as it is
  // used to pass LR. On exit (epilog) it is used to pass x20
  // and accordingly gum_exec_ctx_write_epilog() restores it there.
  gum_arm64_writer_put_ldr_reg_reg_offset (cw,
      ARM64_REG_LR, ARM64_REG_SP, 8);

  // Store SP[8] = X20. We have read the value of LR which was put
  // there by gum_exec_ctx_write_prolog() and are writing x20 there
  // so that it can be restored by code written by
  // gum_exec_ctx_write_epilog()
  gum_arm64_writer_put_str_reg_reg_offset (cw,
      ARM64_REG_X20, ARM64_REG_SP, 8);

  if (type == GUM_PROLOG_MINIMAL)
  {
    // Store all of the FP/NEON registers. NEON is the SIMD engine
    // on the ARM core which allows operations to be carried out
    // on multiple inputs at once.
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q6, ARM64_REG_Q7);

    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q4, ARM64_REG_Q5);

    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q2, ARM64_REG_Q3);

    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q0, ARM64_REG_Q1);

    immediate_for_sp += 4 * 32;

    // x29 is Frame Pointer
    // x30 is the Link Register
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X29, ARM64_REG_X30);

    // We are using STP here to push pairs of registers. We actually
    // have an odd number to push, so we just push STALKER_REG_CTX
    // as padding to make up the numbers
    /* X19 - X28 are callee-saved registers */

    // If we are only calling compiled C code, then the compiler
    // will ensure that should a function use registers x19
    // through x28 then their values will be preserved. Hence,
    // we don't need to store them here as they will not be
    // modified. If however, we make a callout, then we want
    // the stalker end user to have visibility of the full
    // register set and to be able to make any modifications
    // they see fit to them.
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X18, ARM64_REG_X30);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw,
       ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw,
       ARM64_REG_X0, ARM64_REG_X1);
    immediate_for_sp += 11 * 16;
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.q[128] */
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q6, ARM64_REG_Q7);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q0, ARM64_REG_Q1);

    /* GumCpuContext.x[29] + fp + lr + padding */
    // x29 is Frame Pointer
    // x30 is the Link Register
    // x15 is pushed just for padding again
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X30, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X28, ARM64_REG_X29);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X26, ARM64_REG_X27);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X24, ARM64_REG_X25);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X22, ARM64_REG_X23);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X20, ARM64_REG_X21);

    // Store x19 (currently holding the LR value for this function
    // to return to, the address of the caller written by
    // gum_exec_ctx_write_prolog()) in x20 temporarily. We have
    // already pushed x20 so we can use it freely, but we want to
    // push the app's value of x19 into the context. This was
    // pushed onto the stack by the code in
    // gum_exec_ctx_write_prolog() so we can restore it from there
    // before we push it.
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X20, ARM64_REG_X19);

    // Restore X19 from the value pushed by the prolog before the
    // call to the helper.
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        ARM64_REG_X19, ARM64_REG_SP,
        (6 * 16) + (4 * 32));

    // Push the app's values of x18 and x19. x18 was unmodified. We
    // have corrected x19 above.
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X18, ARM64_REG_X19);

    // Restore x19 from x20
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X19, ARM64_REG_X20);

    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_X1);

    /* GumCpuContext.pc + sp */

    // We are going to store the PC and SP here. The PC is set to
    // zero, for the SP, we have to calculate the original SP
    // before we stored all of this context information. Note we
    // use the zero register here (a special register in AArch64
    // which always has the value 0).
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_XZR);
    gum_arm64_writer_put_add_reg_reg_imm (cw,
        ARM64_REG_X1, ARM64_REG_SP,
        (16 * 16) + (4 * 32) + 16 + GUM_RED_ZONE_SIZE);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_X1);

    immediate_for_sp += sizeof (GumCpuContext) + 8;
  }

  // Store the Arithmetic Logic Unit flags into x15. Whilst it might
  // appear that the above add instruction used to calculate the
  // original stack pointer may have changed the flags, AArch64 has
  // an ADD instruction which doesn't modify the condition flags
  // and an ADDS instruction which does.
  gum_arm64_writer_put_instruction (cw, mrs_x15_nzcv);

  /* conveniently point X20 at the beginning of the saved
     registers */
  // X20 is used later by functions such as
  // gum_exec_ctx_load_real_register_from_full_frame_into() to emit
  // code which references the saved frame.
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X20, ARM64_REG_SP);

  /* padding + status */
  // This pushes the flags to ensure that they can be restored
  // correctly after executing inside of stalker.
  gum_arm64_writer_put_push_reg_reg (cw,
      ARM64_REG_X14, ARM64_REG_X15);
  immediate_for_sp += 1 * 16;

  // We saved our LR into x19 on entry so that we could branch back
  // to the instrumented code once this helper has run. Although
  // the instrumented code called us, we restored LR to its previous
  // value before the helper was called (the app code). Although the
  // LR is not callee-saved (e.g. it is not our responsibility to
  // save and restore it on return, but rather that of our caller),
  // it is done here to minimize the code size of the inline stub in
  // the instrumented block.
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X19);
}
```

Now let's look at the epilogue:

```
static void
gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  // This instruction is used to restore the value of x15 back into
  // the ALU flags.
  const guint32 msr_nzcv_x15 = 0xd51b420f;

  /* padding + status */
  // Note that we don't restore the flags yet, since we must wait
  // until we have finished all operations (e.g. additions,
  // subtractions etc) which may modify the flags. However, we
  // must do so before we restore x15 back to its original value.
  gum_arm64_writer_put_pop_reg_reg (cw,
      ARM64_REG_X14, ARM64_REG_X15);

  if (type == GUM_PROLOG_MINIMAL)
  {
    // Save the LR in X19 so we can return back to our caller in the
    // instrumented block. Note that we must restore the link
    // register X30 back to its original value (the block in the app
    // code) before we return. This is carried out below. Recall our
    // value of X19 is saved to the stack by the inline prolog
    // itself and restored by the inline prolog to which we are
    // returning. So we can continue to use it as scratch space
    // here.
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X19, ARM64_REG_LR);

    /* restore status */
    // We have completed all of our instructions which may alter the
    // flags.
    gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);

    // Restore all of the registers we saved in the context. We
    // pushed x30 earlier as padding, but we will
    // pop it back there before we pop the actual pushed value
    // of x30 immediately after.
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X18, ARM64_REG_X30);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X29, ARM64_REG_X30);

    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q0, ARM64_REG_Q1);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q6, ARM64_REG_Q7);
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.pc + sp */
    // We stored the stack pointer and PC in the stack, but we don't
    // want to restore the PC back to the user code, and our stack
    // pointer should be naturally restored as all of the data
    // pushed onto it are popped back off.
    gum_arm64_writer_put_add_reg_reg_imm (cw,
        ARM64_REG_SP, ARM64_REG_SP, 16);

    /* restore status */
    // Again, we have finished any flag affecting operations now that the
    // above addition has been completed.
    gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);

    /* GumCpuContext.x[29] + fp + lr + padding */
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X18, ARM64_REG_X19);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X20, ARM64_REG_X21);

    // Recall that X19 and X20 are actually restored by the epilog
    // itself since X19 is used as scratch space during the
    // prolog/epilog helpers and X20 is repurposed by the prolog as
    // a pointer to the context structure. If we have a full prolog
    // then this means that it was so that we could enter a callout
    // which allows the stalker end user to inspect and modify all
    // of the registers. This means that any changes to the
    // registers in the context structure above must be reflected
    // at runtime. Thus since these values are restored from
    // higher up the stack by the epilog, we must overwrite their
    // values there with those from the context structure.
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
        ARM64_REG_X20, ARM64_REG_SP, (5 * 16) + (4 * 32),
        GUM_INDEX_SIGNED_OFFSET);

    // Save the LR in X19 so we can return back to our caller in the
    // instrumented code. Note that we must restore the link
    // register X30 back to its original value before we return.
    // This is carried out below. Recall our value of X19 is saved
    // to the stack by the inline prolog itself and restored by the
    // inline epilogue to which we are returning.
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X19, ARM64_REG_LR);

    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X22, ARM64_REG_X23);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X24, ARM64_REG_X25);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X26, ARM64_REG_X27);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X28, ARM64_REG_X29);

    // Recall that X15 was also pushed as padding alongside X30 when
    // building the prolog. However, the stalker end user can modify
    // the context and hence the value of X15. However this would
    // not affect the duplicate stashed here as padding and hence
    // X15 would be clobbered. Therefore we copy the now restored
    // value of X15 to the location where this copy was stored for
    // padding before restoring both registers from the stack.
    gum_arm64_writer_put_str_reg_reg_offset (cw,
        ARM64_REG_X15, ARM64_REG_SP, 8);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X30, ARM64_REG_X15);

    /* GumCpuContext.q[128] */
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q0, ARM64_REG_Q1);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q6, ARM64_REG_Q7);
  }

  // Now we can return back to to our caller (the inline part of the
  // epilogue) with the LR still set to the original value of the
  // app code.
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X19)
}
```

This is all quite complicated. Partly this is because we have only a single
register to use as scratch space, partly because we want to keep the prologue
and epilogue code stored inline in the instrumented block to a bare minimum, and
partly because our context values can be changed by callouts and the like. But
hopefully it all now makes sense.

## Reading/Writing Context

Now that we have our context saved, whether it was a full context, or just the
minimal one, Stalker may need to read registers from the context to see what
state of the application code was. For example to find the address which a
branch or return instruction was going to branch to so that we can instrument
the block.

When stalker writes the prologue and epilogue code, it does so by calling
`gum_exec_block_open_prolog()` and `gum_exec_block_close_prolog()`. These store the
type of prologue which has been written in `gc->opened_prolog`.

```
static void
gum_exec_block_open_prolog (GumExecBlock * block,
                            GumPrologType type,
                            GumGeneratorContext * gc)
{
  if (gc->opened_prolog >= type)
    return;

  /* We don't want to handle this case for performance reasons */
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);

  gc->opened_prolog = type;

  gum_exec_ctx_write_prolog (block->ctx, type, gc->code_writer);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_NONE)
    return;

  gum_exec_ctx_write_epilog (block->ctx, gc->opened_prolog,
      gc->code_writer);

  gc->opened_prolog = GUM_PROLOG_NONE;
}
```

Therefore when we want to read a register, this can be achieved with the single
function `gum_exec_ctx_load_real_register_into()`. This determines which kind of
prologue is in use and calls the relevant routine accordingly. Note that these
routines don't actually read the registers, they emit code which reads them.

```
static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm64_reg target_register,
                                      arm64_reg source_register,
                                      GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_MINIMAL)
  {
    gum_exec_ctx_load_real_register_from_minimal_frame_into (ctx,
        target_register, source_register, gc);
    return;
  }
  else if (gc->opened_prolog == GUM_PROLOG_FULL)
  {
    gum_exec_ctx_load_real_register_from_full_frame_into (ctx,
        target_register, source_register, gc);
    return;
  }

  g_assert_not_reached ();
}
Reading registers from the full frame is actually the simplest. We can see the
code closely matches the structure used to pass the context to callouts etc.
Remember that in each case register `x20` points to the base of the context
structure.

```
typedef GumArm64CpuContext GumCpuContext;

struct _GumArm64CpuContext
{
  guint64 pc;
  guint64 sp;

  guint64 x[29];
  guint64 fp;
  guint64 lr;
  guint8 q[128];
};

static void
gum_exec_ctx_load_real_register_from_full_frame_into (
    GumExecCtx * ctx,
    arm64_reg target_register,
    arm64_reg source_register,
    GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 &&
      source_register <= ARM64_REG_X28)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, x) +
        ((source_register - ARM64_REG_X0) * 8));
  }
  else if (source_register == ARM64_REG_X29)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, fp));
  }
  else if (source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw,
        target_register, source_register);
  }
}
```

Reading from the minimal context is actually a little harder. `x0` through `x18`
are simple, they are stored in the context block. After `x18` is 8 bytes padding
(to make a total of 10 pairs of registers) followed by `x29` and `x30`. This
makes a total of 11 pairs of registers. Immediately following this is the
NEON/floating point registers (totallng 128 bytes). Finally `x19` and `x20`, are
stored above this as they are restored by the inline epilogue code written by
`gum_exec_ctx_write_epilog()`.

```
static void
gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx,
    arm64_reg target_register,
    arm64_reg source_register,
    GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 &&
      source_register <= ARM64_REG_X18)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        (source_register - ARM64_REG_X0) * 8);
  }
  else if (source_register == ARM64_REG_X19 ||
      source_register == ARM64_REG_X20)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        (11 * 16) + (4 * 32) +
        ((source_register - ARM64_REG_X19) * 8));
  }
  else if (source_register == ARM64_REG_X29 ||
      source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        (10 * 16) + ((source_register - ARM64_REG_X29) * 8));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw,
        target_register, source_register);
  }
}
```

## Control flow

Execution of stalker begins at one of 3 entry points:
* `_gum_stalker_do_follow_me()`
* `gum_stalker_infect()`
* `gum_exec_ctx_replace_current_block_with()`

The first two we have already covered, these initialize the stalker engine and
start instrumenting the first block of execution.
`gum_exec_ctx_replace_current_block_with()` is used to instrument subsequent
blocks. In fact, the main difference between this function and the preceding
two is that the stalker engine has already been initialized and hence this work
doesn't need to be repeated. All three call `gum_exec_ctx_obtain_block_for()` to
generate the instrumented block.

We covered `gum_exec_ctx_obtain_block_for()` previously in our section on
transformers. It calls the transformed implementation in use, which by default
calls `gum_stalker_iterator_next()` which calls the relocator using
`gum_arm64_relocator_read_one()` to read the next relocated instruction. Then it
calls `gum_stalker_iterator_keep()` to generate the instrumented copy. It does
this in a loop until `gum_stalker_iterator_next()` returns `FALSE` as it has reached
the end of the block.

Most of the time `gum_stalker_iterator_keep()` will simply call
`gum_arm64_relocator_write_one()` to emit the relocated instruction as is.
However, if the instruction is a branch or return instruction it will call
`gum_exec_block_virtualize_branch_insn()` or `gum_exec_block_virtualize_ret_insn()`
respectively. These two virtualization functions which we will cover in more
detail later, emit code to transfer control back into
`gum_exec_ctx_replace_current_block_with()` via an entry gate ready to process the
next block (unless there is an optimization where we can bypass stalker and go
direct to the next instrumented block, or we are entering into an excluded
range).

## Gates

Entry gates are generated by macro, one for each of the different instruction
types found at the end of a block. When we virtualize each of these types of
instruction, we direct control flow back to the
`gum_exec_ctx_replace_current_block_with()` function via one of these gates. We
can see that the implementation of the gate is quite simple, it updates a
counter of how many times it has been called and passes control to
`gum_exec_ctx_replace_current_block_with()` passing through the parameters it was
called with, the `GumExecCtx` and the `start_address` of the next block to be
instrumented.

```
static gboolean counters_enabled = FALSE;
static guint total_transitions = 0;

#define GUM_ENTRYGATE(name) \
  gum_exec_ctx_replace_current_block_from_##name
#define GUM_DEFINE_ENTRYGATE(name) \
  static guint total_##name##s = 0; \
  \
  static gpointer GUM_THUNK \
  GUM_ENTRYGATE (name) ( \
      GumExecCtx * ctx, \
      gpointer start_address) \
  { \
    if (counters_enabled) \
      total_##name##s++; \
    \
    return gum_exec_ctx_replace_current_block_with (ctx, \
        start_address); \
  }
#define GUM_PRINT_ENTRYGATE_COUNTER(name) \
  g_printerr ("\t" G_STRINGIFY (name) "s: %u\n", total_##name##s)
```

These counters can be displayed by the following routine. They are only meant
to be used by the test-suite rather than being exposed to the user through the
API.

```
#define GUM_PRINT_ENTRYGATE_COUNTER(name) \
  g_printerr ("\t" G_STRINGIFY (name) "s: %u\n", total_##name##s)

void
gum_stalker_dump_counters (void)
{
  g_printerr ("\n\ntotal_transitions: %u\n", total_transitions);

  GUM_PRINT_ENTRYGATE_COUNTER (call_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (call_reg);
  GUM_PRINT_ENTRYGATE_COUNTER (post_call_invoke);
  GUM_PRINT_ENTRYGATE_COUNTER (excluded_call_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (excluded_call_reg);
  GUM_PRINT_ENTRYGATE_COUNTER (ret);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_reg);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cc);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cbz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cbnz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_tbz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_tbnz);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_continuation);
}
```
## Virtualize functions

Let's now look in more detail at the *virtualizing* we have for replacing the
branch instruction we find at the end of each block. We have four of these
functions:
* `gum_exec_block_virtualize_branch_insn`
* `gum_exec_block_virtualize_ret_insn`
* `gum_exec_block_virtualize_sysenter_insn`
* `gum_exec_block_virtualize_linux_sysenter`

We can see that two of these relate to to syscalls (and in fact, one calls the
other), we will cover these later. Let's look at the ones for branches and
returns.

### gum_exec_block_virtualize_branch_insn()

This routine first determines whether the destination of the branch comes from
an immediate offset in the instruction, or a register. In the case of the
latter, we don't extract the value just yet, we only determine which register.
This is referred to as the `target`. The next section of the function deals with
branch instructions. This includes both conditional and non-conditional
branches. For conditional targets the destination if the branch is not taken is
referred to as `cond_target`, this is set to the address of the next instruction
in the original block.

Likewise `regular_entry_func` and `cond_entry_func` are used to hold the entry
gates which will be used to handle the branch. The former is used to hold the
gate used for non-conditional branches and `cond_entry_func` holds the gate to
be used for a conditional branch (whether it is taken or not).

The function `gum_exec_block_write_jmp_transfer_code()` is used to write the code
required to branch to the entry gate. For non-conditional branches this is
simple, we call the function passing the `target` and the `regular_entry_func`.
For conditional branches things are slightly more complicated. Our output looks
like the following pseudo-code:

```
  INVERSE_OF_ORIGINAL_BRANCH(is_false)
  jmp_transfer_code(target, cond_entry_func)
is_false:
  jmp_transfer_code(cond_target, cond_entry_func)
```

Here, we can see that we first write a branch instruction into our instrumented
block, as in our instrumented block, we also need to determine whether we should
take the branch or not. But instead of branching directly to the target, just
like for the non-conditional branches we use
`gum_exec_block_write_jmp_transfer_code()` to write code to jump back into stalker
via the relevant entry gate passing the real address we would have branched to.
Note, however that the branch is inverted from the original (e.g. `CBZ` would be
replaced by `CBNZ`).

Now, let's look at how `gum_exec_block_virtualize_branch_insn()` handles calls.
First we emit code to generate the call event if we are configured to. Next we
check if there are any probes in use. If there are, then we call
`gum_exec_block_write_call_probe_code()` to emit the code necessary to call any
registered probe callback. Next, we check if the call is to an excluded range
(note that we can only do this if the call is to an immediate address), if it is
then we emit the instruction as is. But we follow this by using
`gum_exec_block_write_jmp_transfer_code()` as we did when handling branches to
emit code to call back into Stalker right after to instrument the block at the
return address. Note that here we use the `excluded_call_imm` entry gate.

Finally, if it is just a normal call expression, then we use the function
`gum_exec_block_write_call_invoke_code()` to emit the code to handle the call.
This function is pretty complicated as a result of all of the optimization for
backpatching, so we will only look at the basics.

Remember earlier that in `gum_exec_block_virtualize_branch_insn()`, we could only
check if our call was to an excluded range if the target was specified in an
immediate? Well if the target was specified in a register, then here we emit
code to check whether the target is in an excluded range. This is done by
loading the target regsiter using
`gum_exec_ctx_write_push_branch_target_address` (which in turn calls
`gum_exec_ctx_load_real_register_into` which we covered ealier to read the
context) and emitting code to call `gum_exec_block_check_address_for_exclusion`
whose implementation is quite self explanatory. If it is excluded then a branch
is taken and similar code to that described when handling excluded immediate
calls discussed above is used.

Next we emit code to call the entry gate and generate the instrumented block of
the callee. Then call the helper `last_stack_push` to add our `GumExecFrame` to
our context containing the original and instrumented block address. The real and
instrumented code addresses are read from the current cursor positions of the
GeneratorContext and CodeWriter respectively, and we then generate the required
instrumented block for the return address (this is the optimization we covered
earlier, we can jump straight to this block when executing the virtualized
return statement rather than re-entering stalker). Lastly we use
`gum_exec_block_write_exec_generated_code()` to emit code to branch to the
instrumented callee.

### gum_exec_block_virtualize_ret_insn()

After looking at the virtualization of call instructions, you will be pleased to
know that this one is relatively simple! If configured, this function calls
`gum_exec_block_write_ret_event_code()` to generate an event for the return
statement. Then calls `gum_exec_block_write_ret_transfer_code` to generate the
code required to handle the return instruction. This one is simple too, it emits
code to call the `last_stack_pop_and_go` helper we covered earlier.

## Emitting events

Events are one of the key outputs of the stalker engine. They are emitted by the
following functions. Their implementation again is quite self-explanatory:

* `gum_exec_ctx_emit_call_event`
* `gum_exec_ctx_emit_ret_event`
* `gum_exec_ctx_emit_exec_event`
* `gum_exec_ctx_emit_block_event`

One thing to note with each of these functions, however, is that they all call
`gum_exec_block_write_unfollow_check_code()` to generate code for checking if
stalker is to stop following the thread. We'll have a look at this in more
detail next.

## Unfollow and tidy up

If we look at the function which generates the instrumented code to check if we
are being asked to unfollow, we can see it cause the thread to call
`gum_exec_ctx_maybe_unfollow` passing the address of the next instruction to be
instrumented. We can see that if the state has been set to stop following, then
we simply branch back to the original code.

```
static void
gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
                                          GumGeneratorContext * gc,
                                          GumCodeContext cc)
{
  GumExecCtx * ctx = block->ctx;
  GumArm64Writer * cw = gc->code_writer;
  gconstpointer beach = cw->code + 1;
  GumPrologType opened_prolog;

  if (cc != GUM_CODE_INTERRUPTIBLE)
    return;

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_maybe_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin));
  gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X0, beach);

  opened_prolog = gc->opened_prolog;
  gum_exec_block_close_prolog (block, gc);
  gc->opened_prolog = opened_prolog;

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw,
      ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, beach);
}

static gboolean
gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
                             gpointer resume_at)
{
  if (g_atomic_int_get (&ctx->state) !=
      GUM_EXEC_CTX_UNFOLLOW_PENDING)
    return FALSE;

  if (ctx->pending_calls > 0)
    return FALSE;

  gum_exec_ctx_unfollow (ctx, resume_at);

  return TRUE;
}

static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
  ctx->current_block = NULL;

  ctx->resume_at = resume_at;

  gum_tls_key_set_value (ctx->stalker->exec_ctx, NULL);

  ctx->destroy_pending_since = g_get_monotonic_time ();
  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_DESTROY_PENDING);
}
```

A quick note about pending calls. If we have a call to an excluded range, then
we emit the original call in the instrumented code followed by a call back to
Stalker. Whilst the thread is running in the excluded range, however, we cannot
control the instruction pointer until it returns. We therefore need to simply
keep track of these and wait for the thread to exit the excluded range.

Now we can see how a running thread gracefully goes back to running normal
uninstrumented code, let's see how we stop stalking in the first place. We have
two possible ways to stop stalking:

* `gum_stalker_unfollow_me`
* `gum_stalker_unfollow`

The first is quite simple, we set the state to stop following. Then call
`gum_exec_ctx_maybe_unfollow` to attempt to stop the current thread from being
follow and then dispose of the stalker context.
```
void
gum_stalker_unfollow_me (GumStalker * self)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return;

  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_UNFOLLOW_PENDING);

  if (!gum_exec_ctx_maybe_unfollow (ctx, NULL))
    return;

  g_assert (ctx->unfollow_called_while_still_following);

  gum_stalker_destroy_exec_ctx (self, ctx);
}
```

We notice here that we pass NULL as the address to `gum_exec_ctx_maybe_unfollow`
which may seem odd, but we can see that in this instance it isn't used as when
we instrument a block (remember `gum_exec_ctx_replace_current_block_with` is
where the entry gates direct us to instrument subsequent blocks) we check to see
if we are about to call `gum_unfollow_me` and if so then we return the original
block from the function rather than the address of the instrumented block
generated by `gum_exec_ctx_obtain_block_for`. Therefore we can see that this is
a special case and this function isn't stalked. We simply jump to the real
function so at this point we have stopped stalking the thread forever. This
handling differs from excluded ranges as for those we retain the original call
instruction in an instrumented block, but then follow it with a call back into
stalker. In this case, we are just vectoring back to an original uninstrumented
block:
```

static gpointer gum_unfollow_me_address;

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  ...
  gum_unfollow_me_address = gum_strip_code_pointer (
      gum_stalker_unfollow_me);
  ...
}

static gpointer
gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
                                         gpointer start_address)
{
  ...

  if (start_address == gum_unfollow_me_address ||
      start_address == gum_deactivate_address)
  {
    ctx->unfollow_called_while_still_following = TRUE;
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  ...

  else
  {
    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx,
        start_address, &ctx->resume_at);

    ...
  }

  return ctx->resume_at;

  ...
}
```

Let's look at `gum_stalker_unfollow()` now:

```
void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_unfollow_me (self);
  }
  else
  {
    GSList * cur;

    GUM_STALKER_LOCK (self);

    for (cur = self->contexts; cur != NULL; cur = cur->next)
    {
      GumExecCtx * ctx = (GumExecCtx *) cur->data;

      if (ctx->thread_id == thread_id &&
          g_atomic_int_compare_and_exchange (&ctx->state,
              GUM_EXEC_CTX_ACTIVE,
              GUM_EXEC_CTX_UNFOLLOW_PENDING))
      {
        GUM_STALKER_UNLOCK (self);

        if (!gum_exec_ctx_has_executed (ctx))
        {
          GumDisinfectContext dc;

          dc.exec_ctx = ctx;
          dc.success = FALSE;

          gum_process_modify_thread (thread_id,
              gum_stalker_disinfect, &dc);

          if (dc.success)
            gum_stalker_destroy_exec_ctx (self, ctx);
        }

        return;
      }
    }

    GUM_STALKER_UNLOCK (self);
  }
}
```

This function looks through the list of contexts looking for the one for the
requested thread. Again, it sets the state of the context to
`GUM_EXEC_CTX_UNFOLLOW_PENDING`. If the thread has already run, we must wait for
it to check this flag and return to normal execution. However, if it has not run
(perhaps it was in a blocking syscall when we asked to follow it and never got
infected in the first instance) then we can *disinfect* it ourselves by calling
`gum_process_modify_thread` to modify the thread context (this function was
described in detail earlier) and using `gum_stalker_disinfect` as our callback
to perform the changes. This simply checks to see if the program counter was set
to point to the `infect_thunk` and resets the program pointer back to its
original value. The `infect_thunk` is created by `gum_stalker_infect` which is
the callback used by `gum_stalker_follow` to modify the context. Recall that
whilst some of the setup can be carried out on behalf of the target thread, some
has to be done in the context of the target thread itself (in particular
setting variables in thread local storage). Well, it is the `infect_thunk`
which contains that code.

## Miscellaneous

Hopefully we have now covered the most important aspects of stalker and have
provided a good background on how it works. We do have a few other observations
though, which may be of interest.

### Exclusive Store

The AArch64 architecture has support for [exclusive load/store
instructions](https://static.docs.arm.com/100934/0100/armv8_a_synchronization_primitives_100934_0100_en.pdf)
. These instructions are intended to be used for synchronization. If an exclusive
load is performed from a given address, then later attempts an exclusive store
to the same location, then the CPU is able to detect any other stores (exclusive
or otherwise) to the same location in the intervening period and the store
fails.

Obviously, these types of primitives are likely to be used for constructs such
as mutexes and semaphores. Multiple threads may attempt to load the current
count of the semaphore, test whether is it already full, then increment and
store the new value back to take the semaphore. These exclusive operations are
ideal for just such a scenario. Consider though what would happen if multiple
threads are competing for the same resource. If one of those threads were being
traced by stalker, it would always lose the race. Stalker, however, deals with
such a scenario:

```
gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{

  ...

    switch (instruction->ci->id)
    {
      case ARM64_INS_STXR:
      case ARM64_INS_STXP:
      case ARM64_INS_STXRB:
      case ARM64_INS_STXRH:
      case ARM64_INS_STLXR:
      case ARM64_INS_STLXP:
      case ARM64_INS_STLXRB:
      case ARM64_INS_STLXRH:
        gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
        break;
      default:
        break;
    }

    if (gc->exclusive_load_offset != GUM_INSTRUCTION_OFFSET_NONE)
    {
      gc->exclusive_load_offset++;
      if (gc->exclusive_load_offset == 4)
        gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
    }
  }

  ...
  ...
}

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  ...

  switch (insn->id)
  {
    case ARM64_INS_LDAXR:
    case ARM64_INS_LDAXP:
    case ARM64_INS_LDAXRB:
    case ARM64_INS_LDAXRH:
    case ARM64_INS_LDXR:
    case ARM64_INS_LDXP:
    case ARM64_INS_LDXRB:
    case ARM64_INS_LDXRH:
      gc->exclusive_load_offset = 0;
      break;
    default:
      break;
  }

  ...
}
```

Here, we can see that the iterator records when it sees an exclusive load and
tracks how many instructions have passed since. This is continued for up to four
instructions – as this was determined by empirical testing based on how many
instructions would be needed to load, test, modify and store the value. This is
then used to
prevent any instrumentation being emitted which isn't strictly necessary:

```
  if ((ec->sink_mask & GUM_EXEC) != 0 &&
      gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
  {
    gum_exec_block_write_exec_event_code (block, gc,
        GUM_CODE_INTERRUPTIBLE);
  }
```

### Exhausted Blocks

Whilst we check to ensure a minimum amount of space for our current instrumented
block is left in the slab before we start (and allocate a new one if we fall
below this minimum), we cannot predict how long a sequence of instructions we
are likely to encounter in our input block. Nor is it simple to detemine exactly
how many instructions in output we will need to write the necessary
instrumentation (we have possible code for emitting the different types of
event, checking for excluded ranges, virtualizing instructions found at the end
of the block etc.). Also, trying to allow for the instrumented code to be
non-sequential is fraught with difficulty. So the approach taken is to ensure
that each time we read a new instruction from the iterator there is at least
1024 bytes of space in the slab for our output. If it is not the case, then we store the
current address in `continuation_real_address` and return `FALSE` so that the
iterator ends.

```
#define GUM_EXEC_BLOCK_MIN_SIZE 1024

static gboolean
gum_exec_block_is_full (GumExecBlock * block)
{
  guint8 * slab_end = block->slab->data + block->slab->size;

  return slab_end - block->code_end < GUM_EXEC_BLOCK_MIN_SIZE;
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  ...

    if (gum_exec_block_is_full (block))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

  ...
}
```

Our caller `gum_exec_ctx_obtain_block_for()` which is walking the iterator to
generate the block then acts exactly as if there was a branch instruction to the
next instruction, essentially terminating the current block and starting the
next one.

```
static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address_ptr)
{
  ...

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.absolute_address = gc.continuation_real_address;
    continue_target.reg = ARM64_REG_INVALID;
    gum_exec_block_write_jmp_transfer_code (block, &continue_target,
        GUM_ENTRYGATE (jmp_continuation), &gc);
  }

  ...
}
```

It is as if the following instructions had been encountered in the input right
before the instruction which would have not had sufficient space:
```
  B label
label:
```

### Syscall Virtualization

Syscalls are entry points from user-mode into kernel-mode. It is how
applications ask the kernel carry out operations on its behalf, whether that be
opening files or reading network sockets. On AArch64 systems, this is carried
out using the `SVC` instruction, whereas on Intel the instruction is `sysenter`.
Hence the terms syscall and sysenter here are used synonymously.

Syscall virtualization is carried out by the following routine. We can see we
only do anything on Linux systems:

```
static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  return gum_exec_block_virtualize_linux_sysenter (block, gc);
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}
```

This is required because of the `clone` syscall. This syscall creates a new
process which shares execution context with the parent, such as file handles,
virtual address space, and signal handlers. In essence, this effectively creates
a new thread. But the current thread is being traced by stalker, and clone is
going to create an exact replica of it. Given that stalker contexts are on a
per-thread basis, we should not be stalking this new child.

Note that for syscalls in AArch64 the first 8 arguments are passed in registers
`x0` through `x7` and the syscall number is passed in `x8`, additional arguments
are passed on the stack. The return value for the syscall is returned in `x0`.
The function `gum_exec_block_virtualize_linux_sysenter()` generates the necessary
instrumented code to deal with such a syscall. We will look at the pseudo
code below:

```
if x8 == __NR_clone:
  x0 = do_original_syscall()
  if x0 == 0:
    goto gc->instruction->begin
  return x0
else:
  return do_original_syscall()
```

We can see that it first checks if we are dealing with a `clone` syscall,
otherwise it simply performs the original syscall and that is all (the original
syscall instruction is copied from the original block). Otherwise if it is a
clone syscall, then we again perform the original syscall. At this point, we
have two threads of execution, the syscall determines that each thread will
[return a different value](http://man7.org/linux/man-pages/man2/clone.2.html).
The original thread will receive the child's PID as its return value, whereas
the child will receive the value of 0.

If we receive a non-zero value, we can simply continue as we were. We want to
continue stalking the thread and allow execution to carry on with the next
instruction. If, however, we receive a return value of 0, then we are in the
child thread. We therefore carry out a branch to the next instruction in the
original block ensuring that the child continues to run without any interruption
from stalker.

### Pointer Authentication

Last of all, we should note that newer versions of iOS have
[introduced](https://ivrodriguez.com/pointer-authentication-on-armv8-3/)
[pointer authentication
codes](https://events.static.linuxfound.org/sites/events/files/slides/slides_23.pdf).
Pointer authentication codes (PACs) make use of unused bits in pointers (the
high bits of virtual addresses are commonly unused as most systems have a
maximum of 48-bits of virtual address space) to store authentication values.
These values are calculated by using the original pointer, a context parameter
(typically the contents of another register) and a cryptographic key. The idea
is that the key cannot be read or written from user-mode, and the resulting
pointer authentication code cannot be guessed without having access to it.

Let's look at the following fragment of code:

```
pacia lr, sp
stp fp, lr, [sp, #-FRAME_SIZE]!
mov fp, sp

...

ldp fp, lr, [sp], #FRAME_SIZE
autia lr, sp
ret lr
```

The `pacia` instruction combines the values of `LR`, `SP` and the key to
generate a version of `LR` with the authentication code `LR'` and stores back
into the `LR` register. This value is stored in the stack and later restored at
the end of the function. The `autia` instruction validates the value of `LR'`.
This is possible since the PAC in the high bits of `LR` can be stripped to give
the original `LR` value and the pointer authentication code can be regenerated
as it was before using `SP` and the key. The result is checked against `LR'`. If
the value doesn't match then the instruction generates a fault. Thus if the
value of `LR` stored in the stack is modified, or the stack pointer itself is
corrupted then the validation will fail. This is useful to prevent the building
of ROP chains which require return addresses to be stored in the stack. Since
`LR'` is now stored in the stack instead of `LR`, valid return addresses cannot
be forged without the key.

FRIDA needs to take this into account also when generating code. When reading
pointers from registers used by the application (e.g. to determine the
destination of an indirect branch or return), it is necessary to strip these
pointer authentication codes from the address before it is used. This is
achieved using the function `gum_arm64_writer_put_xpaci_reg()`.
