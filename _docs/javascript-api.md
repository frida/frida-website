---
layout: docs
title: JavaScript API
permalink: /docs/javascript-api/
---

## Table of contents
  1. [Global](#global)
  1. [console](#console)
  1. [rpc](#rpc)
  1. [Frida](#frida)
  1. [Script](#script)
  1. [Process](#process)
  1. [Module](#module)
  1. [ModuleMap](#modulemap)
  1. [Memory](#memory)
  1. [MemoryAccessMonitor](#memoryaccessmonitor)
  1. [Thread](#thread)
  1. [Int64](#int64)
  1. [UInt64](#uint64)
  1. [NativePointer](#nativepointer)
  1. [NativeFunction](#nativefunction)
  1. [NativeCallback](#nativecallback)
  1. [SystemFunction](#systemfunction)
  1. [Socket](#socket)
  1. [SocketListener](#socketlistener)
  1. [SocketConnection](#socketconnection)
  1. [IOStream](#iostream)
  1. [InputStream](#inputstream)
  1. [OutputStream](#outputstream)
  1. [UnixInputStream](#unixinputstream)
  1. [UnixOutputStream](#unixoutputstream)
  1. [Win32InputStream](#win32inputstream)
  1. [Win32OutputStream](#win32outputstream)
  1. [File](#file)
  1. [SqliteDatabase](#sqlitedatabase)
  1. [SqliteStatement](#sqlitestatement)
  1. [Interceptor](#interceptor)
  1. [Stalker](#stalker)
  1. [ApiResolver](#apiresolver)
  1. [DebugSymbol](#debugsymbol)
  1. [Instruction](#instruction)
  1. [Kernel](#kernel)
  1. [ObjC](#objc)
  1. [Java](#java)
  1. [WeakRef](#weakref)
  1. [X86Writer](#x86writer)
  1. [X86Relocator](#x86relocator)
  1. [x86 enum types](#x86enums)
  1. [ArmWriter](#armwriter)
  1. [ArmRelocator](#armrelocator)
  1. [ThumbWriter](#thumbwriter)
  1. [ThumbRelocator](#thumbrelocator)
  1. [ARM enum types](#armenums)
  1. [Arm64Writer](#arm64writer)
  1. [Arm64Relocator](#arm64relocator)
  1. [AArch64 enum types](#arm64enums)
  1. [MipsWriter](#mipswriter)
  1. [MipsRelocator](#mipsrelocator)
  1. [MIPS enum types](#mipsenums)

## Global

+   `hexdump(target[, options])`: generate a hexdump from the provided
    *ArrayBuffer* or *NativePointer* `target`, optionally with `options` for
    customizing the output.

    For example:

{% highlight js %}
var libc = Module.findBaseAddress('libc.so');
console.log(hexdump(libc, {
  offset: 0,
  length: 64,
  header: true,
  ansi: true
}));
{% endhighlight %}

{% highlight sh %}
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010  03 00 28 00 01 00 00 00 00 00 00 00 34 00 00 00  ..(.........4...
00000020  34 a8 04 00 00 00 00 05 34 00 20 00 08 00 28 00  4.......4. ...(.
00000030  1e 00 1d 00 06 00 00 00 34 00 00 00 34 00 00 00  ........4...4...
{% endhighlight %}

+   `int64(v)`: short-hand for `new Int64(v)`

+   `uint64(v)`: short-hand for `new UInt64(v)`

+   `ptr(s)`: short-hand for `new NativePointer(s)`

+   `NULL`: short-hand for `ptr("0")`

+   `recv([type, ]callback)`: request `callback` to be called on the next
    message received from your Frida-based application. Optionally `type` may
    be specified to only receive a message where the `type` field is set to
    `type`.

    This will only give you one message, so you need to call `recv()` again
    to receive the next one.

+   `send(message[, data])`: send the JavaScript object `message` to your
    Frida-based application (it must be serializable to JSON). If you also have
    some raw binary data that you'd like to send along with it, e.g. you dumped
    some memory using `NativePointer#readByteArray`, then you may pass this
    through the optional `data` argument. This requires it to either be an
    ArrayBuffer or an array of integers between 0 and 255.

<div class="note">
  <h5>Performance considerations</h5>
  <p>
    While <i>send()</i> is asynchronous, the total overhead of sending a single
    message is not optimized for high frequencies, so that means Frida leaves
    it up to you to batch multiple values into a single <i>send()</i>-call,
    based on whether low delay or high throughput is desired.
  </p>
</div>

+   `setTimeout(func, delay[, ...parameters])`: call `func` after `delay`
    milliseconds, optionally passing it one or more `parameters`.
    Returns an id that can be passed to `clearTimeout` to cancel it.

+   `clearTimeout(id)`: cancel id returned by call to `setTimeout`.

+   `setInterval(func, delay[, ...parameters])`: call `func` every `delay`
    milliseconds, optionally passing it one or more `parameters`.
    Returns an id that can be passed to `clearInterval` to cancel it.

+   `clearInterval(id)`: cancel id returned by call to `setInterval`.

+   `setImmediate(func[, ...parameters])`: schedules `func` to be called on
    Frida's JavaScript thread as soon as possible, optionally passing it one
    or more `parameters`.
    Returns an id that can be passed to `clearImmediate` to cancel it.

+   `clearImmediate(id)`: cancel id returned by call to `setImmediate`.

+   `gc()`: force garbage collection. Useful for testing `WeakRef.bind()` logic,
    but also sometimes needed when using the Duktape runtime and its default GC
    heuristics proving a bit too lazy.


## console

+   `console.log(line)`, `console.warn(line)`, `console.error(line)`:
    write `line` to the console of your Frida-based application. The exact
    behavior depends on where [frida-core](https://github.com/frida/frida-core)
    is integrated.
    For example, this output goes to *stdout* or *stderr* when using Frida
    through [frida-python](https://github.com/frida/frida-python),
    [qDebug](https://doc.qt.io/qt-5/qdebug.html) when using
    [frida-qml](https://github.com/frida/frida-qml), etc.

    Arguments that are ArrayBuffer objects will be substituted by the result of
    `hexdump()` with default options.


## rpc

+   `rpc.exports`: empty object that you can either replace or insert into to
    expose an RPC-style API to your application. The key specifies the method
    name and the value is your exported function. This function may either
    return a plain value for returning that to the caller immediately, or a
    Promise for returning asynchronously.

>   For example:

{% highlight js %}
'use strict';

rpc.exports = {
    add: function (a, b) {
        return a + b;
    },
    sub: function (a, b) {
        return new Promise(function (resolve) {
            setTimeout(function () {
                resolve(a - b);
            }, 100);
        });
    }
};
{% endhighlight %}

>   From an application using the Node.js bindings this API would be consumed
>   like this:

{% highlight js %}
'use strict';

const frida = require('frida');
const fs = require('fs');
const path = require('path');
const util = require('util');

const readFile = util.promisify(fs.readFile);

let session, script;
async function run () {
  const source = await readFile(path.join(__dirname, '_agent.js'), 'utf8');
  session = await frida.attach('iTunes');
  script = await session.createScript(source);
  script.message.connect(onMessage);
  await script.load();
  console.log(await script.exports.add(2, 3));
  console.log(await script.exports.sub(5, 3));
}

run().catch(onError);

function onError(error) {
  console.error(error.stack);
}

function onMessage(message, data) {
  if (message.type === 'send') {
    console.log(message.payload);
  } else if (message.type === 'error') {
    console.error(message.stack);
  }
}
{% endhighlight %}

>   The Python version would be very similar:

{% highlight py %}
import codecs
import frida

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

session = frida.attach('iTunes')
with codecs.open('./agent.js', 'r', 'utf-8') as f:
    source = f.read()
script = session.create_script(source)
script.on('message', on_message)
script.load()
print(script.exports.add(2, 3))
print(script.exports.sub(5, 3))
session.detach()
{% endhighlight %}

In the example above we used `script.on('message', on_message)` to monitor for any messages from the injected process, JavaScript side.  There are other notifications that you can watch for as well on both the `script` and `session`.  If you want to be notified when the target process exits, use `session.on('detached', your_function)`.


## Frida

+   `Frida.version`: property containing the current Frida version, as a string.

+   `Frida.heapSize`: dynamic property containing the current size of Frida's
    private heap, shared by all scripts and Frida's own runtime. This is useful
    for keeping an eye on how much memory your instrumentation is using out of
    the total consumed by the hosting process.


## Script

+   `Script.runtime`: string property containing the runtime being used.
    Either `DUK` or `V8'`.


## Process

+   `Process.id`: property containing the PID as a number

+   `Process.arch`: property containing the string `ia32`, `x64`, `arm`
    or `arm64`

+   `Process.platform`: property containing the string `windows`,
    `darwin`, `linux` or `qnx`

+   `Process.pageSize`: property containing the size of a virtual memory page
    (in bytes) as a number. This is used to make your scripts more portable.

+   `Process.pointerSize`: property containing the size of a pointer
    (in bytes) as a number. This is used to make your scripts more portable.

+   `Process.codeSigningPolicy`: property containing the string `optional` or
    `required`, where the latter means Frida will avoid modifying existing code
    in memory and will not try to run unsigned code. Currently this property
    will always be set to `optional` unless you are using [Gadget](/docs/gadget)
    and have configured it to assume that code-signing is required. This
    property allows you to determine whether the [Interceptor](#interceptor) API
    is off limits, and whether it is safe to modify code or run unsigned code.

+   `Process.isDebuggerAttached()`: returns a boolean indicating whether a
    debugger is currently attached

+   `Process.getCurrentThreadId()`: get this thread's OS-specific id as a number

+   `Process.enumerateThreads()`: enumerates all threads, returning an array of
    objects containing the following properties:

    -   `id`: OS-specific id
    -   `state`: string specifying either `running`, `stopped`, `waiting`,
        `uninterruptible` or `halted`
    -   `context`: object with the keys `pc` and `sp`, which are
        NativePointer objects specifying EIP/RIP/PC and ESP/RSP/SP,
        respectively, for ia32/x64/arm. Other processor-specific keys
        are also available, e.g. `eax`, `rax`, `r0`, `x0`, etc.

+   `Process.findModuleByAddress(address)`,
    `Process.getModuleByAddress(address)`,
    `Process.findModuleByName(name)`,
    `Process.getModuleByName(name)`:
    returns a [Module](#module) whose *address* or *name* matches the one
    specified. In the event that no such module could be found, the
    *find*-prefixed functions return *null* whilst the *get*-prefixed functions
    throw an exception.

+   `Process.enumerateModules()`: enumerates modules loaded right now, returning
    an array of [Module](#module) objects.

+   `Process.findRangeByAddress(address)`, `getRangeByAddress(address)`:
    return an object with details about the range containing *address*. In the
    event that no such range could be found, *findRangeByAddress()* returns
    *null* whilst *getRangeByAddress()* throws an exception.  See
    `Process.enumerateRanges()` for details about which fields are included.

+   `Process.enumerateRanges(protection|specifier)`: enumerates memory ranges
    satisfying `protection` given as a string of the form: `rwx`, where `rw-`
    means "must be at least readable and writable". Alternatively you may
    provide a `specifier` object with a `protection` key whose value is as
    aforementioned, and a `coalesce` key set to `true` if you'd like neighboring
    ranges with the same protection to be coalesced (the default is `false`;
    i.e. keeping the ranges separate). Returns an array of objects containing
    the following properties:

    -   `base`: base address as a `NativePointer`
    -   `size`: size in bytes
    -   `protection`: protection string (see above)
    -   `file`: (when available) file mapping details as an object
        containing:

        -   `path`: full filesystem path as a string
        -   `offset`: offset in the mapped file on disk, in bytes
        -   `size`: size in the mapped file on disk, in bytes

+   `Process.enumerateMallocRanges()`: just like `enumerateRanges()`, but for
    individual memory allocations known to the system heap.

+   `Process.setExceptionHandler(callback)`: install a process-wide exception
    handler callback that gets a chance to handle native exceptions before the
    hosting process itself does. Called with a single argument, `details`, that
    is an object containing:

    -   `type`: string specifying one of:
        * abort
        * access-violation
        * guard-page
        * illegal-instruction
        * stack-overflow
        * arithmetic
        * breakpoint
        * single-step
        * system
    -   `address`: address where the exception occurred, as a NativePointer
    -   `memory`: if present, is an object containing:
        -   `operation`: the kind of operation that triggered the exception, as
            a string specifying either `read`, `write`, or `execute`
        -   `address`: address that was accessed when the exception occurred, as
            a NativePointer
    -   `context`: object with the keys `pc` and `sp`, which are
        NativePointer objects specifying EIP/RIP/PC and ESP/RSP/SP,
        respectively, for ia32/x64/arm. Other processor-specific keys
        are also available, e.g. `eax`, `rax`, `r0`, `x0`, etc.
        You may also update register values by assigning to these keys.
    -   `nativeContext`: address of the OS and architecture-specific CPU context
        struct, as a NativePointer. This is only exposed as a last resort for
        edge-cases where `context` isn't providing enough details. We would
        however discourage using this and rather submit a pull-request to add
        the missing bits needed for your use-case.

    It is up to your callback to decide what to do with the exception. It could
    log the issue, notify your application through a send() followed by a
    blocking recv() for acknowledgement of the sent data being received, or
    it can modify registers and memory to recover from the exception. You should
    return `true` if you did handle the exception, in which case Frida will
    resume the thread immediately. If you do not return `true`, Frida will
    forward the exception to the hosting process' exception handler, if it has
    one, or let the OS terminate the process.


## Module

    Objects returned by e.g. `Module.load()` and `Process.enumerateModules()`.

-   `name`: canonical module name as a string

-   `base`: base address as a `NativePointer`

-   `size`: size in bytes

-   `path`: full filesystem path as a string

-   `enumerateImports()`: enumerates imports of module, returning an array of
    objects containing the following properties:

    -   `type`: string specifying either `function` or `variable`
    -   `name`: import name as a string
    -   `module`: module name as a string
    -   `address`: absolute address as a `NativePointer`
    -   `slot`: memory location where the import is stored, as a
        `NativePointer`

    Only the `name` field is guaranteed to be present for all imports. The
    platform-specific backend will do its best to resolve the other fields
    even beyond what the native metadata provides, but there is no guarantee
    that it will succeed.

-   `enumerateExports()`: enumerates exports of module, returning an array
    of objects containing the following properties:

    -   `type`: string specifying either `function` or `variable`
    -   `name`: export name as a string
    -   `address`: absolute address as a `NativePointer`

-   `enumerateSymbols()`: enumerates symbols of module, returning an array of
    objects containing the following properties:

    -   `isGlobal`: boolean specifying whether symbol is globally visible
    -   `type`: string specifying one of:
        -   unknown
        -   section
        -   undefined (Mach-O)
        -   absolute (Mach-O)
        -   prebound-undefined (Mach-O)
        -   indirect (Mach-O)
        -   object (ELF)
        -   function (ELF)
        -   file (ELF)
        -   common (ELF)
        -   tls (ELF)
    -   `section`: if present, is an object containing:
        -   `id`: string containing section index, segment name (if
                  applicable) and section name – same format as
                  [r2][]'s section IDs
        -   `protection`: protection like in `Process.enumerateRanges()`
    -   `name`: symbol name as a string
    -   `address`: absolute address as a `NativePointer`

<div class="note info">
  <h5>enumerateSymbols() is only available on i/macOS and Linux-based OSes</h5>
  <p>
    We would love to support this on the other platforms too, so if you find
    this useful and would like to help out, please get in touch. You may also
    find the DebugSymbol API adequate, depending on your use-case.
  </p>
</div>

-   `enumerateRanges(protection)`: just like `Process.enumerateRanges`, except
    it's scoped to the module.

-   `findExportByName(exportName)`,
    `getExportByName(exportName)`: returns the absolute address of the export
    named `exportName`. In the event that no such export could be found, the
    *find*-prefixed function returns *null* whilst the *get*-prefixed function
    throws an exception.

+   `Module.load(name)`: loads the specified module and returns a `Module`
    object. Throws an exception if the specified module cannot be loaded.

+   `Module.ensureInitialized(name)`: ensures that initializers of the specified
    module have been run. This is important during early instrumentation, i.e.
    code run early in the process lifetime, to be able to safely interact with
    APIs. One such use-case is interacting with [ObjC](#objc) classes provided
    by a given module.

+   `Module.findBaseAddress(name)`,
    `Module.getBaseAddress(name)`: returns the base address of the `name`
    module. In the event that no such module could be found, the *find*-prefixed
    function returns *null* whilst the *get*-prefixed function throws an
    exception.

+   `Module.findExportByName(moduleName|null, exportName)`,
    `Module.getExportByName(moduleName|null, exportName)`: returns the absolute
    address of the export named `exportName` in `moduleName`. If the module
    isn't known you may pass `null` instead of its name, but this can be a
    costly search and should be avoided. In the event that no such module or
    export could be found, the *find*-prefixed function returns *null* whilst
    the *get*-prefixed function throws an exception.


## ModuleMap

+   `new ModuleMap([filter])`: create a new module map optimized for determining
    which module a given memory address belongs to, if any. Takes a snapshot of
    the currently loaded modules when created, which may be refreshed by calling
    `update()`. The `filter` argument is optional and allows you to pass a
    function used for filtering the list of modules. This is useful if you e.g.
    only care about modules owned by the application itself, and allows you to
    quickly check if an address belongs to one of its modules. The `filter`
    function is passed a [Module](#module) object and must return `true` for
    each module that should be kept in the map. It is called for each loaded
    module every time the map is updated.

-   `has(address)`: check if `address` belongs to any of the contained modules,
    and returns the result as a boolean

-   `find(address)`, `get(address)`: returns a [Module](#module) with details
    about the module that `address` belongs to. In the event that no such module
    could be found, `find()` returns `null` whilst `get()` throws an exception.

-   `findName(address)`,
    `getName(address)`,
    `findPath(address)`,
    `getPath(address)`:
    just like `find()` and `get()`, but only returns the `name` or `path`
    field, which means less overhead when you don't need the other details.

-   `update()`: update the map. You should call this after a module has been
    loaded or unloaded to avoid operating on stale data.

-   `values()`: returns an array with the [Module](#module) objects currently in
    the map. The returned array is a deep copy and will not mutate after a call
    to `update()`.


## Memory

+   `Memory.scan(address, size, pattern, callbacks)`: scan memory for
    occurences of `pattern` in the memory range given by `address` and `size`.

    -   `pattern` must be of the form "13 37 ?? ff" to match 0x13 followed by
        0x37 followed by any byte followed by 0xff.
        For more advanced matching it is also possible to specify an
        [r2][]-style mask. The mask is bitwise AND-ed against both the needle
        and the haystack. To specify the mask append a `:` character after the
        needle, followed by the mask using the same syntax.
        For example: "13 37 13 37 : 1f ff ff f1".
        For convenience it is also possible to specify nibble-level wildcards,
        like "?3 37 13 ?7", which gets translated into masks behind the scenes.

    -   `callbacks` is an object with:

        -   `onMatch: function (address, size)`: called with `address`
            containing the address of the occurence as a `NativePointer` and
            `size` specifying the size as a number.

            This function may return the string `stop` to cancel the memory
            scanning early.

        -   `onError: function (reason)`: called with `reason` when there was a
            memory access error while scanning

        -   `onComplete: function ()`: called when the memory range has been
            fully scanned

-   `Memory.scanSync(address, size, pattern)`: synchronous version of `scan()`
    that returns the matches in an array.

+   `Memory.alloc(size)`: allocate `size` bytes of memory on the heap, or, if
    `size` is a multiple of `Process.pageSize`, one or more raw memory pages
    managed by the OS. The returned value is a `NativePointer` and the
    underlying memory will be released when all JavaScript handles to it are
    gone. This means you need to keep a reference to it while the pointer is
    being used by code outside the JavaScript runtime.

+   `Memory.copy(dst, src, n)`: just like memcpy.

+   `Memory.dup(address, size)`: short-hand for `Memory.alloc()` followed by
    `Memory.copy()`.

+   `Memory.protect(address, size, protection)`: update protection on a region
    of memory, where `protection` is a string of the same format as
    `Process.enumerateRanges()`.

    For example:

{% highlight js %}
Memory.protect(ptr('0x1234'), 4096, 'rw-');
{% endhighlight %}

+   `Memory.patchCode(address, size, apply)`: safely modify `size` bytes at
    `address`, specified as a NativePointer. The supplied JavaScript function
    `apply` gets called with a writable pointer where you must write the desired
    modifications before returning. Do not make any assumptions about this being
    the same location as `address`, as some systems require modifications to be
    written to a temporary location before being mapped into memory on top of
    the original memory page (e.g. on iOS, where directly modifying in-memory
    code may result in the process losing its CS_VALID status).

    For example:

{% highlight js %}
var getLivesLeft = Module.getExportByName('game-engine.so', 'get_lives_left');
var maxPatchSize = 64; // Do not write out of bounds, may be a temporary buffer!
Memory.patchCode(getLivesLeft, maxPatchSize, function (code) {
  var cw = new X86Writer(code, { pc: getLivesLeft });
  cw.putMovRegU32('eax', 9000);
  cw.putRet();
  cw.flush();
});
{% endhighlight %}

+   `Memory.allocUtf8String(str)`,
    `Memory.allocUtf16String(str)`,
    `Memory.allocAnsiString(str)`:
    allocate, encode and write out `str` as a UTF-8/UTF-16/ANSI string on the
    heap. The returned object is a `NativePointer`. See `Memory#alloc` for
    details about its lifetime.


## MemoryAccessMonitor

<div class="note info">
  <h5>MemoryAccessMonitor is only available on Windows for now</h5>
  <p>
    We would love to support this on the other platforms too, so if you find
    this useful and would like to help out, please get in touch.
  </p>
</div>

+   `MemoryAccessMonitor.enable(ranges, callbacks)`: monitor one or more memory
    ranges for access, and notify on the first access of each contained memory
    page. `ranges` is either a single range object or an array of such objects,
    each of which contains:

    -   `base`: base address as a `NativePointer`
    -   `size`: size in bytes

    `callbacks` is an object specifying:

    -   `onAccess: function (details)`: called synchronously with `details`
        object containing:
        -   `operation`: the kind of operation that triggered the access, as a
            string specifying either `read`, `write`, or `execute`
        -   `from`: address of instruction performing the access as a
            `NativePointer`
        -   `address`: address being accessed as a `NativePointer`
        -   `rangeIndex`: index of the accessed range in the ranges provided to
            `MemoryAccessMonitor.enable()`
        -   `pageIndex`: index of the accessed memory page inside the specified
            range
        -   `pagesCompleted`: overall number of pages which have been accessed
            so far (and are no longer being monitored)
        -   `pagesTotal`: overall number of pages that were initially monitored

+   `MemoryAccessMonitor.disable()`: stop monitoring the remaining memory ranges
    passed to `MemoryAccessMonitor.enable()`


## Thread

+   `Thread.backtrace([context, backtracer])`: generate a backtrace for the
    current thread, returned as an array of `NativePointer` objects.

    If you call this from Interceptor's `onEnter` or `onLeave` callbacks you
    should provide `this.context` for the optional `context` argument, as it
    will give you a more accurate backtrace. Omitting `context` means the
    backtrace will be generated from the current stack location, which may
    not give you a very good backtrace due to V8's stack frames.
    The optional `backtracer` argument specifies the kind of backtracer to use,
    and must be either `Backtracer.FUZZY` or `Backtracer.ACCURATE`, where the
    latter is the default if not specified. The accurate kind of backtracers
    rely on debugger-friendly binaries or presence of debug information to do a
    good job, whereas the fuzzy backtracers perform forensics on the stack in
    order to guess the return addresses, which means you will get false
    positives, but it will work on any binary.

{% highlight js %}
var f = Module.getExportByName('libcommonCrypto.dylib',
    'CCCryptorCreate');
Interceptor.attach(f, {
  onEnter: function (args) {
    console.log('CCCryptorCreate called from:\n' +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
  }
});
{% endhighlight %}

+   `Thread.sleep(delay)`: suspend execution of the current thread for `delay`
    seconds specified as a number. For example 0.05 to sleep for 50 ms.


## Int64

+   `new Int64(v)`: create a new Int64 from `v`, which is either a number or a
    string containing a value in decimal, or hexadecimal if prefixed with "0x".
    You may use the `int64(v)` short-hand for brevity.

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    make a new Int64 with this Int64 plus/minus/and/or/xor `rhs`, which may
    either be a number or another Int64

-   `shr(n)`, `shl(n)`:
    make a new Int64 with this Int64 shifted right/left by `n` bits

-   `compare(rhs)`: returns an integer comparison result just like
    String#localeCompare()

-   `toNumber()`: cast this Int64 to a number

-   `toString([radix = 10])`: convert to a string of optional radix (defaults to
    10)


## UInt64

+   `new UInt64(v)`: create a new UInt64 from `v`, which is either a number or a
    string containing a value in decimal, or hexadecimal if prefixed with "0x".
    You may use the `uint64(v)` short-hand for brevity.

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    make a new UInt64 with this UInt64 plus/minus/and/or/xor `rhs`, which may
    either be a number or another UInt64

-   `shr(n)`, `shl(n)`:
    make a new UInt64 with this UInt64 shifted right/left by `n` bits

-   `compare(rhs)`: returns an integer comparison result just like
    String#localeCompare()

-   `toNumber()`: cast this UInt64 to a number

-   `toString([radix = 10])`: convert to a string of optional radix (defaults to
    10)


## NativePointer

+   `new NativePointer(s)`: creates a new NativePointer from the string `s`
    containing a memory address in either decimal, or hexadecimal if prefixed
    with '0x'. You may use the `ptr(s)` short-hand for brevity.

-   `isNull()`: returns a boolean allowing you to conveniently check if a
    pointer is NULL

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    makes a new NativePointer with this NativePointer plus/minus/and/or/xor
    `rhs`, which may either be a number or another NativePointer

-   `shr(n)`, `shl(n)`:
    makes a new NativePointer with this NativePointer shifted right/left by `n`
    bits

-   `not()`: makes a new NativePointer with this NativePointer's bits inverted

-   `equals(rhs)`: returns a boolean indicating whether `rhs` is equal to
    this one; i.e. it has the same pointer value

-   `compare(rhs)`: returns an integer comparison result just like
    String#localeCompare()

-   `toInt32()`: casts this NativePointer to a signed 32-bit integer

-   `toString([radix = 16])`: converts to a string of optional radix (defaults
    to 16)

-   `toMatchPattern()`: returns a string containing a `Memory.scan()`-compatible
    match pattern for this pointer's raw value

-   `readPointer()`: reads a `NativePointer` from this memory location.

    A JavaScript exception will be thrown if the address isn't readable.

-   `writePointer(ptr)`: writes `ptr` to this memory location.

    A JavaScript exception will be thrown if the address isn't writable.

-   `readS8()`, `readU8()`,
    `readS16()`, `readU16()`,
    `readS32()`, `readU32()`,
    `readShort()`, `readUShort()`,
    `readInt()`, `readUInt()`,
    `readFloat()`, `readDouble()`:
    reads a signed or unsigned 8/16/32/etc. or float/double value from
    this memory location and returns it as a number.

    A JavaScript exception will be thrown if the address isn't readable.

-   `writeS8(value)`, `writeU8(value)`,
    `writeS16(value)`, `writeU16(value)`,
    `writeS32(value)`, `writeU32(value)`,
    `writeShort(value)`, `writeUShort(value)`,
    `writeInt(value)`, `writeUInt(value)`,
    `writeFloat(value)`, `writeDouble(value)`:
    writes a signed or unsigned 8/16/32/etc. or float/double `value` to this
    memory location.

    A JavaScript exception will be thrown if the address isn't writable.

-   `readS64()`, `readU64()`,
    `readLong()`, `readULong()`:
    reads a signed or unsigned 64-bit, or long-sized, value from this memory
    location and returns it as an [Int64](#int64)/[UInt64](#uint64) value.

    A JavaScript exception will be thrown if the address isn't readable.

-   `writeS64(value)`, `writeU64(value)`,
    `writeLong(value)`, `writeULong(value)`:
    writes the [Int64](#int64)/[UInt64](#uint64) `value` to this memory
    location.

    A JavaScript exception will be thrown if the address isn't writable.

-   `readByteArray(length)`: reads `length` bytes from this memory location, and
    returns it as an *ArrayBuffer*. This buffer may be efficiently transferred
    to your Frida-based application by passing it as the second argument to
    `send()`.

    A JavaScript exception will be thrown if any of the `length` bytes read from
    the address isn't readable.

-   `writeByteArray(bytes)`: writes `bytes` to this memory location, where
    `bytes` is either an *ArrayBuffer*, typically returned from
    `readByteArray()`, or an array of integers between 0 and 255. For example:
    `[ 0x13, 0x37, 0x42 ]`.

    A JavaScript exception will be thrown if any of the bytes written to
    the address isn't writable.

-   `readCString([size = -1])`,
    `readUtf8String([size = -1])`,
    `readUtf16String([length = -1])`,
    `readAnsiString([size = -1])`:
    reads the bytes at this memory location as an ASCII, UTF-8, UTF-16, or ANSI
    string. Supply the optional `size` argument if you know the size of the
    string in bytes, or omit it or specify *-1* if the string is NUL-terminated.
    Likewise you may supply the optional `length` argument if you know the
    length of the string in characters.

    A JavaScript exception will be thrown if any of the `size` / `length` bytes
    read from the address isn't readable.

    Note that `readAnsiString()` is only available (and relevant) on Windows.

-   `writeUtf8String(str)`,
    `writeUtf16String(str)`,
    `writeAnsiString(str)`:
    encodes and writes the JavaScript string to this memory location (with
    NUL-terminator).

    A JavaScript exception will be thrown if any of the bytes written to
    the address isn't writable.

    Note that `writeAnsiString()` is only available (and relevant) on Windows.


## NativeFunction

+   `new NativeFunction(address, returnType, argTypes[, abi])`: create a new
    NativeFunction to call the function at `address` (specified with a
    `NativePointer`), where `returnType` specifies the return type, and the
    `argTypes` array specifies the argument types. You may optionally also
    specify `abi` if not system default. For variadic functions, add a `'...'`
    entry to `argTypes` between the fixed arguments and the variadic ones.

    ### Structs & Classes by Value

    As for structs or classes passed by value, instead of a string provide an
    array containing the struct's field types following each other. You may nest
    these as deep as desired for representing structs inside structs. Note that
    the returned object is also a `NativePointer`, and can thus be passed to
    `Interceptor#attach`.

    This must match the struct/class exactly, so if you have a struct with three
    ints, you must pass `['int', 'int', 'int']`.

    For a class that has virtual methods, the first parameter will be a pointer
    to [the vtable](https://en.wikipedia.org/wiki/Virtual_method_table).

    For C++ scenarios involving a return value that is larger than
    `Process.pointerSize`, a `NativePointer` to preallocated space must be passed
    in as the first parameter. (This scenario is common in WebKit, for example.)

    Example:
{% highlight js %}
// LargeObject HandyClass::friendlyFunctionName();
var friendlyFunctionName = new NativeFunction(friendlyFunctionPtr, 'void', ['pointer', 'pointer']);
var returnValue = Memory.alloc(sizeOfLargeObject);
friendlyFunctionName(returnValue, thisPtr);
{% endhighlight %}

    ### Supported Types

    -   void
    -   pointer
    -   int
    -   uint
    -   long
    -   ulong
    -   char
    -   uchar
    -   float
    -   double
    -   int8
    -   uint8
    -   int16
    -   uint16
    -   int32
    -   uint32
    -   int64
    -   uint64
    -   bool

    ### Supported ABIs

    -   default

    -   Windows 32-bit:
        -   sysv
        -   stdcall
        -   thiscall
        -   fastcall
        -   mscdecl

    - Windows 64-bit:
        -   win64

    - UNIX x86:
        -   sysv
        -   unix64

    - UNIX ARM:
        -   sysv
        -   vfp

+   `new NativeFunction(address, returnType, argTypes[, options])`: just like
    the previous constructor, but where the fourth argument, `options`, is an
    object that may contain one or more of the following keys:

    -   `abi`: same enum as above.
    -   `scheduling`: scheduling behavior as a string. Supported values are:
        -   cooperative: Allow other threads to execute JavaScript code while
                         calling the native function, i.e. let go of the lock
                         before the call, and re-acquire it afterwards.
                         This is the default behavior.
        -   exclusive: Do not allow other threads to execute JavaScript code
                       while calling the native function, i.e. keep holding the
                       JavaScript lock.
                       This is faster but may result in deadlocks.
    -   `exceptions`: exception behavior as a string. Supported values are:
        -   steal: If the called function generates a native exception, e.g.
                   by dereferencing an invalid pointer, Frida will unwind the
                   stack and steal the exception, turning it into a JavaScript
                   exception that can be handled. This may leave the application
                   in an undefined state, but is useful to avoid crashing the
                   process while experimenting.
                   This is the default behavior.
        -   propagate: Let the application deal with any native exceptions that
                       occur during the function call. (Or, the handler
                       installed through `Process.setExceptionHandler()`.)


## NativeCallback

+   `new NativeCallback(func, returnType, argTypes[, abi])`: create a new
    NativeCallback implemented by the JavaScript function `func`, where
    `returnType` specifies the return type, and the `argTypes` array specifies
    the argument types. You may also specify the abi if not system default.
    See `NativeFunction` for details about supported types and abis.
    Note that the returned object is also a `NativePointer`, and can thus be
    passed to `Interceptor#replace`.


## SystemFunction

+   `new SystemFunction(address, returnType, argTypes[, abi])`: just like
    `NativeFunction`, but also provides a snapshot of the thread's last error
    status. The return value is an object wrapping the actual return value as
    `value`, with one additional platform-specific field named either `errno`
    (UNIX) or `lastError` (Windows).

+   `new SystemFunction(address, returnType, argTypes[, options])`: same as
    above but accepting an `options` object like `NativeFunction`'s
    corresponding constructor.


## Socket

+   `Socket.listen([options])`: open a TCP or UNIX listening socket. Returns a
    *Promise* that receives a [SocketListener](#socketlistener).

    Defaults to listening on both IPv4 and IPv6, if supported, and binding on
    all interfaces on a randomly selected TCP port.

    The optional `options` argument is an object that may contain some of the
    following keys:

    -   `family`: address family as a string. Supported values are:
        -   unix
        -   ipv4
        -   ipv6
        Defaults to listening on both `ipv4` and `ipv6` if supported.
    -   `host`: (IP family) IP address as a string. Defaults to all interfaces.
    -   `port`: (IP family) IP port as a number. Defaults to any available.
    -   `type`: (UNIX family) UNIX socket type as a string. Supported types are:
        -   anonymous
        -   path
        -   abstract
        -   abstract-padded
        Defaults to `path`.
    -   `path`: (UNIX family) UNIX socket path as a string.
    -   `backlog`: Listen backlog as a number. Defaults to `10`.

+   `Socket.connect(options)`: connect to a TCP or UNIX server. Returns a
    *Promise* that receives a [SocketConnection](#socketconnection).

    The `options` argument is an object that should contain some of the
    following keys:

    -   `family`: address family as a string. Supported values are:
        -   unix
        -   ipv4
        -   ipv6
        Defaults to an IP family depending on the `host` specified.
    -   `host`: (IP family) IP address as a string. Defaults to `localhost`.
    -   `port`: (IP family) IP port as a number.
    -   `type`: (UNIX family) UNIX socket type as a string. Supported types are:
        -   anonymous
        -   path
        -   abstract
        -   abstract-padded
        Defaults to `path`.
    -   `path`: (UNIX family) UNIX socket path as a string.

+   `Socket.type(handle)`: inspect the OS socket `handle` and return its type
    as a string which is either `tcp`, `udp`, `tcp6`, `udp6`, `unix:stream`,
    `unix:dgram`, or `null` if invalid or unknown.

+   `Socket.localAddress(handle)`,
    `Socket.peerAddress(handle)`:
    inspect the OS socket `handle` and return its local or peer address, or
    `null` if invalid or unknown.

    The object returned has the fields:

    -   `ip`: (IP sockets) IP address as a string.
    -   `port`: (IP sockets) IP port as a number.
    -   `path`: (UNIX sockets) UNIX path as a string.


## SocketListener

    All methods are fully asynchronous and return Promise objects.

-   `path`: (UNIX family) path being listened on.

-   `port`: (IP family) IP port being listened on.

-   `close()`: close the listener, releasing resources related to it. Once the
    listener is closed, all other operations will fail. Closing a listener
    multiple times is allowed and will not result in an error.

-   `accept()`: wait for the next client to connect. The returned *Promise*
    receives a [SocketConnection](#socketconnection).


## SocketConnection

    Inherits from IOStream.
    All methods are fully asynchronous and return Promise objects.

-   `setNoDelay(noDelay)`: disable the Nagle algorithm if `noDelay` is `true`,
    otherwise enable it. The Nagle algorithm is enabled by default, so it is
    only necessary to call this method if you wish to optimize for low delay
    instead of high throughput.


## IOStream

    All methods are fully asynchronous and return Promise objects.

-   `input`: the [InputStream](#inputstream) to read from.

-   `output`: the [OutputStream](#outputstream) to write to.

-   `close()`: close the stream, releasing resources related to it. This will
    also close the individual input and output streams. Once the stream is
    closed, all other operations will fail. Closing a stream multiple times is
    allowed and will not result in an error.


## InputStream

    All methods are fully asynchronous and return Promise objects.

-   `close()`: close the stream, releasing resources related to it. Once the
    stream is closed, all other operations will fail. Closing a stream multiple
    times is allowed and will not result in an error.

-   `read(size)`: read up to `size` bytes from the stream. The returned
    *Promise* receives an *ArrayBuffer* up to `size` bytes long. End of stream
    is signalled through an empty buffer.

-   `readAll(size)`: keep reading from the stream until exactly `size` bytes
    have been consumed. The returned *Promise* receives an *ArrayBuffer* that is
    exactly `size` bytes long. Premature error or end of stream results in the
    *Promise* getting rejected with an error, where the `Error` object has a
    `partialData` property containing the incomplete data.


## OutputStream

    All methods are fully asynchronous and return Promise objects.

-   `close()`: close the stream, releasing resources related to it. Once the
    stream is closed, all other operations will fail. Closing a stream multiple
    times is allowed and will not result in an error.

-   `write(data)`: try to write `data` to the stream. The `data` value is either
    an *ArrayBuffer* or an array of integers between 0 and 255. The returned
    *Promise* receives a *Number* specifying how many bytes of `data` were
    written to the stream.

-   `writeAll(data)`: keep writing to the stream until all of `data` has been
    written. The `data` value is either an *ArrayBuffer* or an array of integers
    between 0 and 255. Premature error or end of stream results in an error,
    where the `Error` object has a `partialSize` property specifying how many
    bytes of `data` were written to the stream before the error occurred.


## UnixInputStream

    (Only available on UNIX-like OSes.)

+   `new UnixInputStream(fd[, options])`: create a new
    [InputStream](#inputstream) from the specified file descriptor `fd`.

    You may also supply an `options` object with `autoClose` set to `true` to
    make the stream close the underlying file descriptor when the stream is
    released, either through `close()` or future garbage-collection.


## UnixOutputStream

    (Only available on UNIX-like OSes.)

+   `new UnixOutputStream(fd[, options])`: create a new
    [OutputStream](#outputstream) from the specified file descriptor `fd`.

    You may also supply an `options` object with `autoClose` set to `true` to
    make the stream close the underlying file descriptor when the stream is
    released, either through `close()` or future garbage-collection.


## Win32InputStream

    (Only available on Windows.)

+   `new Win32InputStream(handle[, options])`: create a new
    [InputStream](#inputstream) from the specified `handle`, which is a Windows
    *HANDLE* value.

    You may also supply an `options` object with `autoClose` set to `true` to
    make the stream close the underlying handle when the stream is released,
    either through `close()` or future garbage-collection.


## Win32OutputStream

    (Only available on Windows.)

+   `new Win32OutputStream(handle[, options])`: create a new
    [OutputStream](#outputstream) from the specified `handle`, which is a
    Windows *HANDLE* value.

    You may also supply an `options` object with `autoClose` set to `true` to
    make the stream close the underlying handle when the stream is released,
    either through `close()` or future garbage-collection.


## File

+   `new File(filePath, mode)`: open or create the file at `filePath` with
    the `mode` string specifying how it should be opened. For example `"wb"`
    to open the file for writing in binary mode (this is the same format as
    `fopen()` from the C standard library).

-   `write(data)`: synchronously write `data` to the file, where `data` is
    either a string or a buffer as returned by `NativePointer#readByteArray`

-   `flush()`: flush any buffered data to the underlying file

-   `close()`: close the file. You should call this function when you're done
    with the file unless you are fine with this happening when the object is
    garbage-collected or the script is unloaded.


## SqliteDatabase

+   `SqliteDatabase.open(path[, options])`: opens the SQLite v3 database
    specified by `path`, a string containing the filesystem path to the
    database. By default the database will be opened read-write, but you may
    customize this behavior by providing an `options` object with a property
    named `flags`, specifying an array of strings containing one or more of the
    following values: `readonly`, `readwrite`, `create`.  The returned
    SqliteDatabase object will allow you to perform queries on the database.

+   `SqliteDatabase.openInline(encodedContents)`: just like `open()` but the
    contents of the database is provided as a string containing its data,
    Base64-encoded. We recommend gzipping the database before Base64-encoding
    it, but this is optional and detected by looking for a gzip magic marker.
    The database is opened read-write, but is 100% in-memory and never touches
    the filesystem. This is useful for agents that need to bundle a cache of
    precomputed data, e.g. static analysis data used to guide dynamic analysis.

-   `close()`: close the database. You should call this function when you're
    done with the database, unless you are fine with this happening when the
    object is garbage-collected or the script is unloaded.

-   `exec(sql)`: execute a raw SQL query, where `sql` is a string containing
    the text-representation of the query. The query's result is ignored, so this
    should only be used for queries for setting up the database, e.g. table
    creation.

-   `prepare(sql)`: compile the provided SQL into a
    [SqliteStatement](#sqlitestatement) object, where `sql` is a string
    containing the text-representation of the query.

    For example:

{% highlight js %}
var db, smt, row, name, bio;

db = SqliteDatabase.open('/path/to/people.db');

smt = db.prepare('SELECT name, bio FROM people WHERE age = ?');

console.log('People whose age is 42:');
smt.bindInteger(1, 42);
while ((row = smt.step()) !== null) {
  name = row[0];
  bio = row[1];
  console.log('Name:', name);
  console.log('Bio:', bio);
}
smt.reset();
{% endhighlight %}

-   `dump()`: dump the database to a gzip-compressed blob encoded as Base64,
    where the result is returned as a string. This is useful for inlining a
    cache in your agent's code, loaded by calling `SqliteDatabase.openInline()`.


## SqliteStatement

-   `bindInteger(index, value)`: bind the integer `value` to `index`
-   `bindFloat(index, value)`: bind the floating point `value` to `index`
-   `bindText(index, value)`: bind the text `value` to `index`
-   `bindBlob(index, bytes)`: bind the blob `bytes` to `index`, where `bytes`
    is an ArrayBuffer, array of byte values, or a string
-   `bindNull(index)`: bind a null value to `index`
-   `step()`: either start a new query and get the first result, or move to the
    next one. Returns an array containing the values in the order specified by
    the query, or `null` when the last result is reached. You should call
    `reset()` at that point if you intend to use this object again.
-   `reset()`: reset internal state to allow subsequent queries


## Interceptor

+   `Interceptor.attach(target, callbacks)`: intercept calls to function at
    `target`. This is a `NativePointer` specifying the address of the function
    you would like to intercept calls to. Note that on 32-bit ARM this address
    must have its least significant bit set to 0 for ARM functions, and 1 for
    Thumb functions. Frida takes care of this detail for you if you get the
    address from a Frida API (for example `Module.getExportByName()`).

    The `callbacks` argument is an object containing one or more of:

    -   `onEnter: function (args)`: callback function given one argument
        `args` that can be used to read or write arguments as an array of
        `NativePointer` objects.

    -   `onLeave: function (retval)`: callback function given one argument
        `retval` that is a `NativePointer`-derived object containing the raw
        return value.
        You may call `retval.replace(1337)` to replace the return value with
        the integer `1337`, or `retval.replace(ptr("0x1234"))` to replace with
        a pointer.
        Note that this object is recycled across *onLeave* calls, so do not
        store and use it outside your callback. Make a deep copy if you need
        to store the contained value, e.g.: `ptr(retval.toString())`.

    You may also intercept arbitrary instructions by passing a function instead
    of the `callbacks` object. This function has the same signature as
    `onEnter`, but the `args` argument passed to it will only give you sensible
    values if the intercepted instruction is at the beginning of a function or
    at a point where registers/stack have not yet deviated from that point.

    Returns a listener object that you can call `detach()` on.

    Note that these functions will be invoked with `this` bound to a
    per-invocation (thread-local) object where you can store arbitrary data,
    which is useful if you want to read an argument in `onEnter` and act on it
    in `onLeave`.

    For example:

{% highlight js %}
Interceptor.attach(Module.getExportByName('libc.so', 'read'), {
  onEnter: function (args) {
    this.fileDescriptor = args[0].toInt32();
  },
  onLeave: function (retval) {
    if (retval.toInt32() > 0) {
      /* do something with this.fileDescriptor */
    }
  }
});
{% endhighlight %}

+   Additionally, the object contains some useful properties:

    -   `returnAddress`: return address as a NativePointer

    -   `context`: object with the keys `pc` and `sp`, which are
        NativePointer objects specifying EIP/RIP/PC and ESP/RSP/SP,
        respectively, for ia32/x64/arm. Other processor-specific keys
        are also available, e.g. `eax`, `rax`, `r0`, `x0`, etc.
        You may also update register values by assigning to these keys.

    -   `errno`: (UNIX) current errno value (you may replace it)

    -   `lastError`: (Windows) current OS error value (you may replace it)

    -   `threadId`: OS thread ID

    -   `depth`: call depth of relative to other invocations

    For example:

{% highlight js %}
Interceptor.attach(Module.getExportByName(null, 'read'), {
  onEnter: function (args) {
    console.log('Context information:');
    console.log('Context  : ' + JSON.stringify(this.context));
    console.log('Return   : ' + this.returnAddress);
    console.log('ThreadId : ' + this.threadId);
    console.log('Depth    : ' + this.depth);
    console.log('Errornr  : ' + this.err);

    // Save arguments for processing in onLeave.
    this.fd = args[0].toInt32();
    this.buf = args[1];
    this.count = args[2].toInt32();
  },
  onLeave: function (result) {
    console.log('----------')
    // Show argument 1 (buf), saved during onEnter.
    var numBytes = result.toInt32();
    if (numBytes > 0) {
      console.log(hexdump(this.buf, { length: numBytes, ansi: true }));
    }
    console.log('Result   : ' + numBytes);
  }
})
{% endhighlight %}

<div class="note">
  <h5>Performance considerations</h5>
  <p>
    The callbacks provided have a significant impact on performance. If you only
    need to inspect arguments but do not care about the return value, or the
    other way around, make sure you omit the callback that you don't need; i.e.
    avoid putting your logic in <i>onEnter</i> and leaving <i>onLeave</i> in
    there as an empty callback.
  </p>
  <p>
    On an iPhone 5S the base overhead when providing just <i>onEnter</i> might be
    something like 6 microseconds, and 11 microseconds with both <i>onEnter</i>
    and <i>onLeave</i> provided.
  </p>
  <p>
    Also be careful about intercepting calls to functions that are called a
    bazillion times per second; while <i>send()</i> is asynchronous, the total
    overhead of sending a single message is not optimized for high frequencies,
    so that means Frida leaves it up to you to batch multiple values into a
    single <i>send()</i>-call, based on whether low delay or high throughput
    is desired.
  </p>
</div>

+   `Interceptor.detachAll()`: detach all previously attached callbacks.

+   `Interceptor.replace(target, replacement)`: replace function at `target`
    with implementation at `replacement`. This is typically used if you want
    to fully or partially replace an existing function's implementation. Use
    `NativeCallback` to implement a `replacement` in JavaScript. Note that
    `replacement` will be kept alive until `Interceptor#revert` is called.
    If you want to chain to the original implementation you can synchronously
    call `target` through a `NativeFunction` inside your implementation, which
    will bypass and go directly to the original implementation.

    Here's an example:

{% highlight js %}
var openPtr = Module.getExportByName('libc.so', 'open');
var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
Interceptor.replace(openPtr, new NativeCallback(function (pathPtr, flags) {
  var path = pathPtr.readUtf8String();
  log('Opening "' + path + '"');
  var fd = open(pathPtr, flags);
  log('Got fd: ' + fd);
  return fd;
}, 'int', ['pointer', 'int']));
{% endhighlight %}

+   `Interceptor.revert(target)`: revert function at `target` to the previous
    implementation.

+   `Interceptor.flush()`: ensure any pending changes have been committed
    to memory. This is should only be done in the few cases where this is
    necessary, e.g. if you just attach()ed to or replace()d a function that you
    are about to call using [NativeFunction](#nativefunction). Pending changes
    are flushed automatically whenever the current thread is about to leave the
    JavaScript runtime or calls send(). This includes any API built on top of
    send(), like when returning from an [RPC](#rpc) method, and calling any
    method on the [console](#console) API.


## Stalker

+   `Stalker.follow([threadId, options])`: start stalking `threadId` (or the
    current thread if omitted), optionally with `options` for enabling events.

    For example:

{% highlight js %}
Stalker.follow(Process.getCurrentThreadId(), {
  events: {
    call: true, // CALL instructions: yes please

    // Other events:
    ret: false, // RET instructions
    exec: false, // all instructions: not recommended as it's
                 //                   a lot of data
    block: false, // block executed: coarse execution trace
    compile: false // block compiled: useful for coverage
  },

  //
  // Only specify one of the two following callbacks.
  // (See note below.)
  //

  //
  // onReceive: Called with `events` containing a binary blob
  //            comprised of one or more GumEvent structs.
  //            See `gumevent.h` for details about the
  //            format. Use `Stalker.parse()` to examine the
  //            data.
  //
  //onReceive: function (events) {
  //},
  //

  //
  // onCallSummary: Called with `summary` being a key-value
  //                mapping of call target to number of
  //                calls, in the current time window. You
  //                would typically implement this instead of
  //                `onReceive()` for efficiency, i.e. when
  //                you only want to know which targets were
  //                called and how many times, but don't care
  //                about the order that the calls happened
  //                in.
  //
  onCallSummary: function (summary) {
  },

  //
  // Advanced users: This is how you can plug in your own
  //                 StalkerTransformer, where the provided
  //                 function is called synchronously
  //                 whenever Stalker wants to recompile
  //                 a basic block of the code that's about
  //                 to be executed by the stalked thread.
  //
  //transform: function (iterator) {
  //  var instruction = iterator.next();
  //
  //  var startAddress = instruction.address;
  //  var isAppCode = startAddress.compare(appStart) >= 0 &&
  //      startAddress.compare(appEnd) === -1;
  //
  //  do {
  //    if (isAppCode && instruction.mnemonic === 'ret') {
  //      iterator.putCmpRegI32('eax', 60);
  //      iterator.putJccShortLabel('jb', 'nope', 'no-hint');
  //
  //      iterator.putCmpRegI32('eax', 90);
  //      iterator.putJccShortLabel('ja', 'nope', 'no-hint');
  //
  //      iterator.putCallout(onMatch);
  //
  //      iterator.putLabel('nope');
  //    }
  //
  //    iterator.keep();
  //  } while ((instruction = iterator.next()) !== null);
  //},
  //
  // The default implementation is just:
  //
  //   while (iterator.next() !== null)
  //     iterator.keep();
  //
  // The example above shows how you can insert your own code
  // just before every `ret` instruction across any code
  // executed by the stalked thread inside the app's own
  // memory range. It inserts code that checks if the `eax`
  // register contains a value between 60 and 90, and inserts
  // a synchronous callout back into JavaScript whenever that
  // is the case. The callback receives a single argument
  // that gives it access to the CPU registers, and it is
  // also able to modify them.
  //
  // function onMatch (context) {
  //   console.log('Match! pc=' + context.pc +
  //       ' rax=' + context.rax.toInt32());
  // }
  //
  // Note that not calling keep() will result in the
  // instruction getting dropped, which makes it possible
  // for your transform to fully replace certain instructions
  // when this is desirable.
  //
});
{% endhighlight %}

<div class="note">
  <h5>Performance considerations</h5>
  <p>
    The callbacks provided have a significant impact on performance. If you only
    need periodic call summaries but do not care about the raw events, or the
    other way around, make sure you omit the callback that you don't need; i.e.
    avoid putting your logic in <i>onCallSummary</i> and leaving
    <i>onReceive</i> in there as an empty callback.
  </p>
</div>

+   `Stalker.unfollow([threadId])`: stop stalking `threadId` (or the current
    thread if omitted).

+   `Stalker.parse(events[, options])`: parse GumEvent binary blob, optionally
    with `options` for customizing the output.

    For example:

{% highlight js %}
  onReceive: function (events) {
    console.log(Stalker.parse(events, {
      annotate: true, // to display the type of event
      stringify: true
        // to format pointer values as strings instead of `NativePointer`
        // values, i.e. less overhead if you're just going to `send()` the 
        // thing not actually parse the data agent-side
    }));
  },
{% endhighlight %}

+   `Stalker.flush()`: flush out any buffered events. Useful when you don't want
    to wait until the next `Stalker.queueDrainInterval` tick.

+   `Stalker.garbageCollect()`: free accumulated memory at a safe point after
    `Stalker#unfollow`. This is needed to avoid race-conditions where the
    thread just unfollowed is executing its last instructions.

+   `Stalker.addCallProbe(address, callback)`: call `callback` (see
    `Interceptor#attach#onEnter` for signature) synchronously when a CALL is
    made to `address`. Returns an id that can be passed to
    `Stalker#removeCallProbe` later.

+   `Stalker.removeCallProbe`: remove a call probe added by
    `Stalker#addCallProbe`.

+   `Stalker.trustThreshold`: an integer specifying how many times a piece of
    code needs to be executed before it is assumed it can be trusted to not
    mutate.
    Specify -1 for no trust (slow), 0 to trust code from the get-go, and N to
    trust code after it has been executed N times. Defaults to 1.

+   `Stalker.queueCapacity`: an integer specifying the capacity of the event
    queue in number of events. Defaults to 16384 events.

+   `Stalker.queueDrainInterval`: an integer specifying the time in milliseconds
    between each time the event queue is drained. Defaults to 250 ms, which
    means that the event queue is drained four times per second.


## ApiResolver

+   `new ApiResolver(type)`: create a new resolver of the given `type`, allowing
    you to quickly find functions by name, with globs permitted. Precisely which
    resolvers are available depends on the current platform and runtimes loaded
    in the current process. As of the time of writing, the available resolvers
    are:

    -   `module`: Resolves exported and imported functions of shared libraries
                  currently loaded. Always available.
    -   `objc`: Resolves Objective-C methods of classes currently loaded.
                Available on macOS and iOS in processes that have the Objective-C
                runtime loaded. Use `ObjC.available` to check at runtime, or
                wrap your `new ApiResolver('objc')` call in a *try-catch*.

    The resolver will load the minimum amount of data required on creation, and
    lazy-load the rest depending on the queries it receives. It is thus
    recommended to use the same instance for a batch of queries, but recreate it
    for future batches to avoid looking at stale data.

-   `enumerateMatches(query)`: performs the resolver-specific `query` string,
    returning an array of objects containing the following properties:

    -   `name`: name of the API that was found
    -   `address`: address as a `NativePointer`

{% highlight js %}
var resolver = new ApiResolver('module');
var matches = resolver.enumerateMatches('exports:*!open*');
var first = matches[0];
/*
 * Where `first` is an object similar to:
 *
 * {
 *   name: '/usr/lib/libSystem.B.dylib!opendir$INODE64',
 *   address: ptr('0x7fff870135c9')
 * }
 */
{% endhighlight %}

{% highlight js %}
var resolver = new ApiResolver('objc');
var matches = resolver.enumerateMatches('-[NSURL* *HTTP*]');
var first = matches[0];
/*
 * Where `first` contains an object like this one:
 *
 * {
 *   name: '-[NSURLRequest valueForHTTPHeaderField:]',
 *   address: ptr('0x7fff94183e22')
 * }
 */
{% endhighlight %}


## DebugSymbol

+   `DebugSymbol.fromAddress(address)`, `DebugSymbol.fromName(name)`:
    look up debug information for `address`/`name` and return it as an object
    containing:

    -   `address`: Address that this symbol is for, as a `NativePointer`.
    -   `name`: Name of the symbol, as a string.
    -   `moduleName`: Module name owning this symbol, as a string.
    -   `fileName`: File name owning this symbol, as a string.
    -   `lineNumber`: Line number in `fileName`, as a number.

    You may also call `toString()` on it, which is very useful when combined
    with `Thread.backtrace()`:

{% highlight js %}
var f = Module.getExportByName('libcommonCrypto.dylib',
    'CCCryptorCreate');
Interceptor.attach(f, {
  onEnter: function (args) {
    console.log('CCCryptorCreate called from:\n' +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
  }
});
{% endhighlight %}

+   `DebugSymbol.getFunctionByName(name)`: resolves a function name and
    returns its address as a `NativePointer`. Returns the first if more than
    one function is found. Throws an exception if the name cannot be resolved.

+   `DebugSymbol.findFunctionsNamed(name)`: resolves a function name and returns
    its addresses as an array of `NativePointer` objects.

+   `DebugSymbol.findFunctionsMatching(glob)`: resolves function names matching
    `glob` and returns their addresses as an array of `NativePointer` objects.


## Instruction

+   `Instruction.parse(target)`: parse the instruction at the `target` address
    in memory, represented by a `NativePointer`.
    Note that on 32-bit ARM this address must have its least significant bit
    set to 0 for ARM functions, and 1 for Thumb functions. Frida takes care
    of this detail for you if you get the address from a Frida API (for
    example `Module.getExportByName()`).

    The object returned has the fields:

    -   `address`: address (EIP) of this instruction, as a `NativePointer`
    -   `next`: pointer to the next instruction, so you can `parse()` it
    -   `size`: size of this instruction
    -   `mnemonic`: string representation of instruction mnemonic
    -   `opStr`: string representation of instruction operands
    -   `operands`: array of objects describing each operand, each specifying
                    the `type` and `value`, at a minimum, but potentially also
                    additional properties depending on the architecture
    -   `regsRead`: array of register names implicitly read by this instruction
    -   `regsWritten`: array of register names implicitly written to by this
        instruction
    -   `groups`: array of group names that this instruction belongs to
    -   `toString()`: convert to a human-readable string

    For details about `operands` and `groups`, please consult the
    [Capstone](http://www.capstone-engine.org/) documentation for your
    architecture.


## Kernel

+   `Kernel.available`: a boolean specifying whether the Kernel API is
    available. Do not invoke any other `Kernel` properties or methods unless
    this is the case.

+   `Kernel.base`: base address of the kernel, as a UInt64.

+   `Kernel.pageSize`: size of a kernel page in bytes, as a number.

+   `Kernel.enumerateModules()`: enumerates kernel modules loaded right now,
    returning an array of objects containing the following properties:

    -   `name`: canonical module name as a string
    -   `base`: base address as a `NativePointer`
    -   `size`: size in bytes

+   `Kernel.enumerateRanges(protection|specifier)`: enumerate kernel memory
    ranges satisfying `protection` given as a string of the form: `rwx`, where
    `rw-` means "must be at least readable and writable". Alternatively you may
    provide a `specifier` object with a `protection` key whose value is as
    aforementioned, and a `coalesce` key set to `true` if you'd like neighboring
    ranges with the same protection to be coalesced (the default is `false`;
    i.e. keeping the ranges separate). Returns an array of objects containing
    the following properties:

    -   `base`: base address as a `NativePointer`
    -   `size`: size in bytes
    -   `protection`: protection string (see above)

+   `Kernel.enumerateModuleRanges(name, protection)`: just like
    `Kernel.enumerateRanges`, except it's scoped to the specified module
    `name` – which may be `null` for the module of the kernel itself. Each
    range also has a `name` field containing a unique identifier as a string.

+   `Kernel.alloc(size)`: allocate `size` bytes of kernel memory, rounded up to
    a multiple of the kernel's page size. The returned value is a `UInt64`
    specifying the base address of the allocation.

+   `Kernel.protect(address, size, protection)`: update protection on a region
    of kernel memory, where `protection` is a string of the same format as
    `Kernel.enumerateRanges()`.

    For example:

{% highlight js %}
Kernel.protect(UInt64('0x1234'), 4096, 'rw-');
{% endhighlight %}

+   `Kernel.readByteArray(address, length)`: just like
    `NativePointer#readByteArray`, but reading from kernel memory.

+   `Kernel.writeByteArray(address, bytes)`: just like
    `NativePointer#writeByteArray`, but writing to kernel memory.

+   `Kernel.scan(address, size, pattern, callbacks)`: just like `Memory.scan`,
    but scanning kernel memory.

-   `Kernel.scanSync(address, size, pattern)`: synchronous version of `scan()`
    that returns the matches in an array.


## ObjC

+   `ObjC.available`: a boolean specifying whether the current process has an
    Objective-C runtime loaded. Do not invoke any other `ObjC` properties or
    methods unless this is the case.

+   `ObjC.api`: an object mapping function names to `NativeFunction` instances
    for direct access to a big portion of the Objective-C runtime API.

+   `ObjC.classes`: an object mapping class names to `ObjC.Object` JavaScript
    bindings for each of the currently registered classes. You can interact with objects by using dot notation and replacing colons with underscores, i.e.: `[NSString stringWithString:@"Hello World"]` becomes `var NSString = ObjC.classes.NSString; NSString.stringWithString_("Hello World");`. Note the underscore after the method name. Refer to iOS Examples section for more details.

+   `ObjC.protocols`: an object mapping protocol names to `ObjC.Protocol`
    JavaScript bindings for each of the currently registered protocols.

+   `ObjC.mainQueue`: the GCD queue of the main thread

+   `ObjC.schedule(queue, work)`: schedule the JavaScript function `work` on
    the GCD queue specified by `queue`. An `NSAutoreleasePool` is created just
    before calling `work`, and cleaned up on return.

{% highlight js %}
var NSSound = ObjC.classes.NSSound; /* macOS */
ObjC.schedule(ObjC.mainQueue, function () {
    var sound = NSSound.alloc().initWithContentsOfFile_byReference_("/Users/oleavr/.Trash/test.mp3", true);
    sound.play();
});
{% endhighlight %}

+   `new ObjC.Object(handle[, protocol])`: create a JavaScript binding given
    the existing object at `handle` (a NativePointer). You may also specify
    the `protocol` argument if you'd like to treat `handle` as an object
    implementing a certain protocol only.

{% highlight js %}
Interceptor.attach(myFunction.implementation, {
  onEnter: function(args) {
    // ObjC: args[0] = self, args[1] = selector, args[2-n] = arguments
    var myString = new ObjC.Object(args[2]);
    console.log("String argument: " + myString.toString());
  }
});
{% endhighlight %}

>   This object has some special properties:
>
>   -   `$kind`: string specifying either `instance`, `class` or `meta-class`
>   -   `$super`: an *ObjC.Object* instance used for chaining up to super-class
>       method implementations
>   -   `$superClass`: super-class as an *ObjC.Object* instance
>   -   `$class`: class of this object as an *ObjC.Object* instance
>   -   `$className`: string containing the class name of this object
>   -   `$protocols`: object mapping protocol name to `ObjC.Protocol` instance
>       for each of the protocols that this object conforms to
>   -   `$methods`: array containing native method names exposed by this object's
>       class and parent classes
>   -   `$ownMethods`: array containing native method names exposed by this object's
>       class, not including parent classes
>   -   `$ivars`: object mapping each instance variable name to its current
>       value, allowing you to read and write each through access and assignment
>
>   There is also an `equals(other)` method for checking whether two instances
>   refer to the same underlying object.

+   `new ObjC.Protocol(handle)`: create a JavaScript binding given the existing
    protocol at `handle` (a NativePointer).

+   `new ObjC.Block(target)`: create a JavaScript binding given the existing
    block at `target` (a NativePointer), or, to define a new block, `target`
    should be an object specifying the type signature and JavaScript function to
    call whenever the block is invoked. The function is specified with an
    `implementation` key, and the signature is specified either through a
    `types` key, or through the `retType` and `argTypes` keys. See
    `ObjC.registerClass()` for details.

    The most common use-case is hooking an existing block, which for a block
    expecting two arguments would look something like:

{% highlight js %}
const pendingBlocks = new Set();

Interceptor.attach(..., {
  onEnter(args) {
    const block = new ObjC.Block(args[4]);
    pendingBlocks.add(block); // Keep it alive
    const appCallback = block.implementation;
    block.implementation = (error, value) => {
      // Do your logging here
      const result = appCallback(error, value);
      pendingBlocks.delete(block);
      return result;
    };
  }
});
{% endhighlight %}

+   `ObjC.implement(method, fn)`: create a JavaScript implementation compatible
    with the signature of `method`, where the JavaScript function `fn` is used
    as the implementation. Returns a `NativeCallback` that you may assign to an
    ObjC method's `implementation` property.

{% highlight js %}
var NSSound = ObjC.classes.NSSound; /* macOS */
var oldImpl = NSSound.play.implementation;
NSSound.play.implementation = ObjC.implement(NSSound.play, function (handle, selector) {
    return oldImpl(handle, selector);
});

var NSView = ObjC.classes.NSView; /* macOS */
var drawRect = NSView['- drawRect:'];
var oldImpl = drawRect.implementation;
drawRect.implementation = ObjC.implement(drawRect, function (handle, selector) {
    oldImpl(handle, selector);
});
{% endhighlight %}

>   As the `implementation` property is a `NativeFunction` and thus also a
>   `NativePointer`, you may also use `Interceptor` to hook functions:

{% highlight js %}
var NSSound = ObjC.classes.NSSound; /* macOS */
Interceptor.attach(NSSound.play.implementation, {
    onEnter: function () {
        send("[NSSound play]");
    }
});
{% endhighlight %}

+   `ObjC.registerProxy(properties)`: create a new class designed to act as a
    proxy for a target object, where `properties` is an object specifying:

    -   `protocols`: (optional) Array of protocols this class conforms to.
    -   `methods`: (optional) Object specifying methods to implement.
    -   `events`: (optional) Object specifying callbacks for getting notified
        about events. For now there's just one event:
        -   `forward: function (name)`: Called with `name` specifying the
            method name that we're about to forward a call to. This might be
            where you'd start out with a temporary callback that just logs the
            names to help you decide which methods to override.

{% highlight js %}
const MyConnectionDelegateProxy = ObjC.registerProxy({
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    '- connection:didReceiveResponse:': function (conn, resp) {
      /* fancy logging code here */
      /* this.data.foo === 1234 */
      this.data.target
          .connection_didReceiveResponse_(conn, resp);
    },
    '- connection:didReceiveData:': function (conn, data) {
      /* other logging code here */
      this.data.target
          .connection_didReceiveData_(conn, data);
    }
  },
  events: {
    forward: function (name) {
      console.log('*** forwarding: ' + name);
    }
  }
});

const method = ObjC.classes.NSURLConnection[
    '- initWithRequest:delegate:startImmediately:'];
Interceptor.attach(method.implementation, {
  onEnter: function (args) {
    args[3] = new MyConnectionDelegateProxy(args[3], {
      foo: 1234
    });
  }
});
{% endhighlight %}

+   `ObjC.registerClass(properties)`: create a new Objective-C class, where
    `properties` is an object specifying:

    -   `name`: (optional) String specifying the name of the class; omit this
        if you don't care about the globally visible name and would like the
        runtime to auto-generate one for you.
    -   `super`: (optional) Super-class, or *null* to create a new root class;
        omit to inherit from *NSObject*.
    -   `protocols`: (optional) Array of protocols this class conforms to.
    -   `methods`: (optional) Object specifying methods to implement.

{% highlight js %}
const MyConnectionDelegateProxy = ObjC.registerClass({
  name: 'MyConnectionDelegateProxy',
  super: ObjC.classes.NSObject,
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    '- init': function () {
      const self = this.super.init();
      if (self !== null) {
        ObjC.bind(self, {
          foo: 1234
        });
      }
      return self;
    },
    '- dealloc': function () {
      ObjC.unbind(this.self);
      this.super.dealloc();
    },
    '- connection:didReceiveResponse:': function (conn, resp) {
      /* this.data.foo === 1234 */
    },
    /*
     * But those previous methods are declared assuming that
     * either the super-class or a protocol we conform to has
     * the same method so we can grab its type information.
     * However, if that's not the case, you would write it
     * like this:
     */
    '- connection:didReceiveResponse:': {
      retType: 'void',
      argTypes: ['object', 'object'],
      implementation: function (conn, resp) {
      }
    },
    /* Or grab it from an existing class: */
    '- connection:didReceiveResponse:': {
      types: ObjC.classes
          .Foo['- connection:didReceiveResponse:'].types,
      implementation: function (conn, resp) {
      }
    },
    /* Or from an existing protocol: */
    '- connection:didReceiveResponse:': {
      types: ObjC.protocols.NSURLConnectionDataDelegate
          .methods['- connection:didReceiveResponse:'].types,
      implementation: function (conn, resp) {
      }
    },
    /* Or write the signature by hand if you really want to: */
    '- connection:didReceiveResponse:': {
      types: 'v32@0:8@16@24',
      implementation: function (conn, resp) {
      }
    }
  }
});

const proxy = MyConnectionDelegateProxy.alloc().init();
/* use `proxy`, and later: */
proxy.release();
{% endhighlight %}

+   `ObjC.registerProtocol(properties)`: create a new Objective-C protocol,
    where `properties` is an object specifying:

    -   `name`: (optional) String specifying the name of the protocol; omit this
        if you don't care about the globally visible name and would like the
        runtime to auto-generate one for you.
    -   `protocols`: (optional) Array of protocols this protocol incorporates.
    -   `methods`: (optional) Object specifying methods to declare.

{% highlight js %}
const MyDataDelegate = ObjC.registerProtocol({
  name: 'MyDataDelegate',
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    /* You must specify the signature: */
    '- connection:didStuff:': {
      retType: 'void',
      argTypes: ['object', 'object']
    },
    /* Or grab it from a method of an existing class: */
    '- connection:didStuff:': {
      types: ObjC.classes
          .Foo['- connection:didReceiveResponse:'].types
    },
    /* Or from an existing protocol method: */
    '- connection:didStuff:': {
      types: ObjC.protocols.NSURLConnectionDataDelegate
          .methods['- connection:didReceiveResponse:'].types
    },
    /* Or write the signature by hand if you really want to: */
    '- connection:didStuff:': {
      types: 'v32@0:8@16@24'
    },
    /* You can also make a method optional (default is required): */
    '- connection:didStuff:': {
      retType: 'void',
      argTypes: ['object', 'object'],
      optional: true
    }
  }
});
{% endhighlight %}

+   `ObjC.bind(obj, data)`: bind some JavaScript data to an Objective-C
    instance; see `ObjC.registerClass()` for an example.

+   `ObjC.unbind(obj)`: unbind previous associated JavaScript data from an
    Objective-C instance; see `ObjC.registerClass()` for an example.

+   `ObjC.getBoundData(obj)`: look up previously bound data from an Objective-C
    object.

+   `ObjC.enumerateLoadedClasses([options, ]callbacks)`: enumerate classes
    loaded right now, where `callbacks` is an object specifying:

    -   `onMatch: function (name, owner)`: called for each loaded class with the
        `name` of the class as a string, and `owner` specifying the path to the
        module where the class was loaded from. To obtain a JavaScript wrapper
        for a given class, do: `ObjC.classes[name]`.

    -   `onComplete: function ()`: called when all classes have been enumerated.

    For example:

{% highlight js %}
ObjC.enumerateLoadedClasses({
  onMatch: function (name, owner) {
    console.log('onMatch:', name, owner);
  },
  onComplete: function () {
  }
});
{% endhighlight %}

    The optional `options` argument is an object where you may specify the
    `ownedBy` property to limit enumeration to modules in a given `ModuleMap`.

    For example:

{% highlight js %}
var appModules = new ModuleMap(isAppModule);
ObjC.enumerateLoadedClasses({ ownedBy: appModules }, {
  onMatch: function (name, owner) {
    console.log('onMatch:', name, owner);
  },
  onComplete: function () {
  }
});

function isAppModule(m) {
  return !/^\/(usr\/lib|System|Developer)\//.test(m.path);
}
{% endhighlight %}

+   `ObjC.enumerateLoadedClassesSync([options])`: synchronous version of
    `enumerateLoadedClasses()` that returns an object mapping owner module to
    an array of class names.

    For example:

{% highlight js %}
var appModules = new ModuleMap(isAppModule);
var appClasses = ObjC.enumerateLoadedClassesSync({ ownedBy: appModules });
console.log('appClasses:', JSON.stringify(appClasses));

function isAppModule(m) {
  return !/^\/(usr\/lib|System|Developer)\//.test(m.path);
}
{% endhighlight %}

+   `ObjC.choose(specifier, callbacks)`: enumerate live instances of classes
    matching `specifier` by scanning the heap. `specifier` is either a class
    selector or an object specifying a class selector and desired options.
    The class selector is an *ObjC.Object* of a class, e.g.
    *ObjC.classes.UIButton*.
    When passing an object as the specifier you should provide the `class`
    field with your class selector, and the `subclasses` field with a
    boolean indicating whether you're also interested in subclasses matching the
    given class selector. The default is to also include subclasses.
    The `callbacks` argument is an object specifying:

    -   `onMatch: function (instance)`: called once for each live instance found
        with a ready-to-use `instance` just as if you would have called
        `new ObjC.Object(ptr("0x1234"))` knowing that this particular
        Objective-C instance lives at *0x1234*.

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function ()`: called when all instances have been enumerated

+   `ObjC.chooseSync(specifier)`: synchronous version of `choose()` that returns
    the instances in an array.

+   `ObjC.selector(name)`: convert the JavaScript string `name` to a selector

+   `ObjC.selectorAsString(sel)`: convert the selector `sel` to a JavaScript
    string


## Java

+   `Java.available`: a boolean specifying whether the current process has the
    a Java VM loaded, i.e. Dalvik or ART. Do not invoke any other `Java`
    properties or methods unless this is the case.

+   `Java.androidVersion`: a string specifying which version of Android we're
    running on.

+   `Java.enumerateLoadedClasses(callbacks)`: enumerate classes loaded right
    now, where `callbacks` is an object specifying:

    -   `onMatch: function (className)`: called for each loaded class with
        `className` that may be passed to `use()` to get a JavaScript wrapper.

    -   `onComplete: function ()`: called when all classes have been enumerated.

+   `Java.enumerateLoadedClassesSync()`: synchronous version of
    `enumerateLoadedClasses()` that returns the class names in an array.

+   `Java.enumerateClassLoaders(callbacks)`: enumerate class loaders present
    in the Java VM, where `callbacks` is an object specifying:

    -   `onMatch: function (loader)`: called for each class loader with
        `loader`, a wrapper for the specific `java.lang.ClassLoader`.

    -   `onComplete: function ()`: called when all class loaders have been
        enumerated.

    You may assign such a loader to `Java.classFactory.loader` to make
    `Java.use()` look for classes on a specific loader instead of the default
    loader used by the app.

+   `Java.enumerateClassLoadersSync()`: synchronous version of
    `enumerateClassLoaders()` that returns the class loaders in an array.

+   `Java.scheduleOnMainThread(fn)`: run `fn` on the main thread of the VM.

+   `Java.perform(fn)`: ensure that the current thread is attached to the VM
    and call `fn`. (This isn't necessary in callbacks from Java.)
    Will defer calling `fn` if the app's class loader is not available yet.
    Use `Java.performNow()` if access to the app's classes is not needed.

{% highlight js %}
Java.perform(function () {
  var Activity = Java.use('android.app.Activity');
  Activity.onResume.implementation = function () {
    send('onResume() got called! Let's call the original implementation');
    this.onResume();
  };
});
{% endhighlight %}

+   `Java.performNow(fn)`: ensure that the current thread is attached to the
    VM and call `fn`. (This isn't necessary in callbacks from Java.)

+   `Java.use(className)`: dynamically get a JavaScript wrapper for
    `className` that you can instantiate objects from by calling `$new()` on
    it to invoke a constructor. Call `$dispose()` on an instance to clean it
    up explicitly (or wait for the JavaScript object to get garbage-collected,
    or script to get unloaded). Static and non-static methods are available,
    and you can even replace a method implementation and throw an exception
    from it:

{% highlight js %}
Java.perform(function () {
  var Activity = Java.use('android.app.Activity');
  var Exception = Java.use('java.lang.Exception');
  Activity.onResume.implementation = function () {
    throw Exception.$new('Oh noes!');
  };
});
{% endhighlight %}

    Uses the app's class loader by default, but you may customize this by
    assigning a different loader instance to `Java.classFactory.loader`.

+   `Java.openClassFile(filePath)`: open the .dex file at `filePath`, returning
    an object with the following methods:

    -   `load()`: load the contained classes into the VM.

    -   `getClassNames()`: obtain an array of available class names.

+   `Java.choose(className, callbacks)`: enumerate live instances of the
    `className` class by scanning the Java heap, where `callbacks` is an
    object specifying:

    -   `onMatch: function (instance)`: called with each live instance found
        with a ready-to-use `instance` just as if you would have called
        `Java.cast()` with a raw handle to this particular instance.

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function ()`: called when all instances have been enumerated

+   `Java.cast(handle, klass)`: create a JavaScript wrapper given the existing
    instance at `handle` of given class `klass` as returned from `Java.use()`.
    Such a wrapper also has a `class` property for getting a wrapper for its
    class, and a `$className` property for getting a string representation of
    its class-name.

{% highlight js %}
var Activity = Java.use('android.app.Activity');
var activity = Java.cast(ptr('0x1234'), Activity);
{% endhighlight %}

+   `Java.array(type, elements)`: creates a Java array with elements of the
     specified `type`, from a JavaScript array `elements`. The resulting Java
     array behaves like a JS array, but can be passed by reference to Java APIs
     in order to allow them to modify its contents.

{% highlight js %}
var values = Java.array('int', [ 1003, 1005, 1007 ]);

var JString = Java.use('java.lang.String');
var str = JString.$new(Java.array('byte', [ 0x48, 0x65, 0x69 ]));
{% endhighlight %}

+   `Java.isMainThread()`: determine whether the caller is running on the main
    thread.

+   `Java.registerClass(spec)`: create a new Java class and return a wrapper for
    it, where `spec` is an object containing:

    -   `name`: String specifying the name of the class.
    -   `implements`: (optional) Array of interfaces implemented by this class.
    -   `methods`: (optional) Object specifying methods to implement.

{% highlight js %}
var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

var MyTrustManager = Java.registerClass({
  name: 'com.example.MyTrustManager',
  implements: [X509TrustManager],
  methods: {
    checkClientTrusted: function (chain, authType) {
    },
    checkServerTrusted: function (chain, authType) {
    },
    getAcceptedIssuers: function () {
      return [];
    },
  }
});

var MyWeirdTrustManager = Java.registerClass({
  name: 'com.example.MyWeirdTrustManager',
  implements: [X509TrustManager],
  methods: {
    checkClientTrusted: function (chain, authType) {
      console.log('checkClientTrusted');
    },
    checkServerTrusted: [{
      returnType: 'void',
      argumentTypes: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String'],
      implementation: function (chain, authType) {
        console.log('checkServerTrusted A');
      }
    }, {
      returnType: 'java.util.List',
      argumentTypes: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'],
      implementation: function (chain, authType, host) {
        console.log('checkServerTrusted B');
        return null;
      }
    }],
    getAcceptedIssuers: function () {
      console.log('getAcceptedIssuers');
      return [];
    },
  }
});
{% endhighlight %}

+   `Java.deoptimizeEverything()`: forces the VM to execute everything with
    its interpreter. Necessary to prevent optimizations from bypassing method
    hooks in some cases, and allows ART's Instrumentation APIs to be used for
    tracing the runtime.

+   `Java.vm`: object with the following methods:

    -   `perform(fn)`: ensures that the current thread is attached to the VM and
        calls `fn`. (This isn't necessary in callbacks from Java.)

    -   `getEnv()`: gets a wrapper for the current thread's `JNIEnv`. Throws an
        exception if the current thread is not attached to the VM.

    -   `tryGetEnv()`: tries to get a wrapper for the current thread's `JNIEnv`.
        Returns `null` if the current thread is not attached to the VM.

+   `Java.classFactory`: object with the following properties:

    -   `loader`: wrapper for the class loader currently being used. Typically
        updated by the first call to `Java.perform()`.

        You may assign a different `java.lang.ClassLoader` to make `Java.use()`
        look for classes on a specific loader instead of the default loader used
        by the app.

    -   `cacheDir`: string containing path to cache directory currently being
        used. Typically updated by the first call to `Java.perform()`.

    -   `tempFileNaming`: object specifying naming convention to use for
        temporary files. Defaults to `{ prefix: 'frida', suffix: 'dat' }`.


## WeakRef

+   `WeakRef.bind(value, fn)`: monitor `value` and call the `fn` callback as
    soon as `value` has been garbage-collected, or the script is about to get
    unloaded. Returns an id that you can pass to `WeakRef.unbind()` for
    explicit cleanup.

    This API is useful if you're building a language-binding, where you need to
    free native resources when a JS value is no longer needed.

+   `WeakRef.unbind(id)`: stop monitoring the value passed to
    `WeakRef.bind(value, fn)`, and call the `fn` callback immediately.


## X86Writer

+   `new X86Writer(codeAddress[, { pc: ptr('0x1234') }])`: create a new code
    writer for generating x86 machine code written directly to memory at
    `codeAddress`, specified as a NativePointer.
    The second argument is an optional options object where the initial program
    counter may be specified, which is useful when generating code to a scratch
    buffer. This is essential when using `Memory.patchCode()` on iOS, which may
    provide you with a temporary location that later gets mapped into memory at
    the intended memory location.

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `flush()`: resolve label references and write pending data to memory. You
    should always call this once you've finished generating code. It is usually
    also desirable to do this between pieces of unrelated code, e.g. when
    generating multiple functions in one go.

-   `base`: memory location of the first byte of output, as a NativePointer

-   `code`: memory location of the next byte of output, as a NativePointer

-   `pc`: program counter at the next byte of output, as a NativePointer

-   `offset`: current offset as a JavaScript Number

-   `putLabel(id)`: put a label at the current position, where `id` is a string
    that may be referenced in past and future `put*Label()` calls

-   `putCallAddressWithArguments(func, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putCallAddressWithAlignedArguments(func, args)`: like above, but also
    ensures that the argument list is aligned on a 16 byte boundary

-   `putCallRegWithArguments(reg, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putCallRegWithAlignedArguments(reg, args)`: like above, but also
    ensures that the argument list is aligned on a 16 byte boundary

-   `putCallRegOffsetPtrWithArguments(reg, offset, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putCallAddress(address)`: put a CALL instruction

-   `putCallReg(reg)`: put a CALL instruction

-   `putCallRegOffsetPtr(reg, offset)`: put a CALL instruction

-   `putCallIndirect(addr)`: put a CALL instruction

-   `putCallIndirectLabel(labelId)`: put a CALL instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putCallNearLabel(labelId)`: put a CALL instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putLeave()`: put a LEAVE instruction

-   `putRet()`: put a RET instruction

-   `putRetImm(immValue)`: put a RET instruction

-   `putJmpAddress(address)`: put a JMP instruction

-   `putJmpShortLabel(labelId)`: put a JMP instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putJmpNearLabel(labelId)`: put a JMP instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putJmpReg(reg)`: put a JMP instruction

-   `putJmpRegPtr(reg)`: put a JMP instruction

-   `putJmpRegOffsetPtr(reg, offset)`: put a JMP instruction

-   `putJmpNearPtr(address)`: put a JMP instruction

-   `putJccShort(instructionId, target, hint)`: put a JCC instruction

-   `putJccNear(instructionId, target, hint)`: put a JCC instruction

-   `putJccShortLabel(instructionId, labelId, hint)`: put a JCC instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putJccNearLabel(instructionId, labelId, hint)`: put a JCC instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putAddRegImm(reg, immValue)`: put an ADD instruction

-   `putAddRegReg(dstReg, srcReg)`: put an ADD instruction

-   `putAddRegNearPtr(dstReg, srcAddress)`: put an ADD instruction

-   `putSubRegImm(reg, immValue)`: put a SUB instruction

-   `putSubRegReg(dstReg, srcReg)`: put a SUB instruction

-   `putSubRegNearPtr(dstReg, srcAddress)`: put a SUB instruction

-   `putIncReg(reg)`: put an INC instruction

-   `putDecReg(reg)`: put a DEC instruction

-   `putIncRegPtr(target, reg)`: put an INC instruction

-   `putDecRegPtr(target, reg)`: put a DEC instruction

-   `putLockXaddRegPtrReg(dstReg, srcReg)`: put a LOCK XADD instruction

-   `putLockCmpxchgRegPtrReg(dstReg, srcReg)`: put a LOCK CMPXCHG instruction

-   `putLockIncImm32Ptr(target)`: put a LOCK INC IMM32 instruction

-   `putLockDecImm32Ptr(target)`: put a LOCK DEC IMM32 instruction

-   `putAndRegReg(dstReg, srcReg)`: put an AND instruction

-   `putAndRegU32(reg, immValue)`: put an AND instruction

-   `putShlRegU8(reg, immValue)`: put a SHL instruction

-   `putShrRegU8(reg, immValue)`: put a SHR instruction

-   `putXorRegReg(dstReg, srcReg)`: put an XOR instruction

-   `putMovRegReg(dstReg, srcReg)`: put a MOV instruction

-   `putMovRegU32(dstReg, immValue)`: put a MOV instruction

-   `putMovRegU64(dstReg, immValue)`: put a MOV instruction

-   `putMovRegAddress(dstReg, address)`: put a MOV instruction

-   `putMovRegPtrU32(dstReg, immValue)`: put a MOV instruction

-   `putMovRegOffsetPtrU32(dstReg, dstOffset, immValue)`: put a MOV instruction

-   `putMovRegPtrReg(dstReg, srcReg)`: put a MOV instruction

-   `putMovRegOffsetPtrReg(dstReg, dstOffset, srcReg)`: put a MOV instruction

-   `putMovRegRegPtr(dstReg, srcReg)`: put a MOV instruction

-   `putMovRegRegOffsetPtr(dstReg, srcReg, srcOffset)`: put a MOV instruction

-   `putMovRegBaseIndexScaleOffsetPtr(dstReg, baseReg, indexReg, scale, offset)`: put a MOV instruction

-   `putMovRegNearPtr(dstReg, srcAddress)`: put a MOV instruction

-   `putMovNearPtrReg(dstAddress, srcReg)`: put a MOV instruction

-   `putMovFsU32PtrReg(fsOffset, srcReg)`: put a MOV FS instruction

-   `putMovRegFsU32Ptr(dstReg, fsOffset)`: put a MOV FS instruction

-   `putMovGsU32PtrReg(fsOffset, srcReg)`: put a MOV GS instruction

-   `putMovRegGsU32Ptr(dstReg, fsOffset)`: put a MOV GS instruction

-   `putMovqXmm0EspOffsetPtr(offset)`: put a MOVQ XMM0 ESP instruction

-   `putMovqEaxOffsetPtrXmm0(offset)`: put a MOVQ EAX XMM0 instruction

-   `putMovdquXmm0EspOffsetPtr(offset)`: put a MOVDQU XMM0 ESP instruction

-   `putMovdquEaxOffsetPtrXmm0(offset)`: put a MOVDQU EAX XMM0 instruction

-   `putLeaRegRegOffset(dstReg, srcReg, srcOffset)`: put a LEA instruction

-   `putXchgRegRegPtr(leftReg, rightReg)`: put an XCHG instruction

-   `putPushU32(immValue)`: put a PUSH instruction

-   `putPushNearPtr(address)`: put a PUSH instruction

-   `putPushReg(reg)`: put a PUSH instruction

-   `putPopReg(reg)`: put a POP instruction

-   `putPushImmPtr(immPtr)`: put a PUSH instruction

-   `putPushax()`: put a PUSHAX instruction

-   `putPopax()`: put a POPAX instruction

-   `putPushfx()`: put a PUSHFX instruction

-   `putPopfx()`: put a POPFX instruction

-   `putTestRegReg(regA, regB)`: put a TEST instruction

-   `putTestRegU32(reg, immValue)`: put a TEST instruction

-   `putCmpRegI32(reg, immValue)`: put a CMP instruction

-   `putCmpRegOffsetPtrReg(regA, offset, regB)`: put a CMP instruction

-   `putCmpImmPtrImmU32(immPtr, immValue)`: put a CMP instruction

-   `putCmpRegReg(regA, regB)`: put a CMP instruction

-   `putClc()`: put a CLC instruction

-   `putStc()`: put a STC instruction

-   `putCld()`: put a CLD instruction

-   `putStd()`: put a STD instruction

-   `putCpuid()`: put a CPUID instruction

-   `putLfence()`: put an LFENCE instruction

-   `putRdtsc()`: put an RDTSC instruction

-   `putPause()`: put a PAUSE instruction

-   `putNop()`: put a NOP instruction

-   `putBreakpoint()`: put an OS/architecture-specific breakpoint instruction

-   `putPadding(n)`: put `n` guard instruction

-   `putNopPadding(n)`: put `n` NOP instructions

-   `putU8(value)`: put a uint8

-   `putS8(value)`: put an int8

-   `putBytes(data)`: put raw data from the provided ArrayBuffer


## X86Relocator

+   `new X86Relocator(inputCode, output)`: create a new code relocator for
    copying x86 instructions from one memory location to another, taking
    care to adjust position-dependent instructions accordingly.
    The source address is specified by `inputCode`, a NativePointer.
    The destination is given by `output`, an [X86Writer](#x86writer) pointed
    at the desired target memory address.

-   `reset(inputCode, output)`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `input`: latest [Instruction](#instruction) read so far. Starts out `null`
    and changes on every call to `readOne()`.

-   `eob`: boolean indicating whether end-of-block has been reached, i.e. we've
    reached a branch of any kind, like CALL, JMP, BL, RET.

-   `eoi`: boolean indicating whether end-of-input has been reached, e.g. we've
    reached JMP/B/RET, an instruction after which there may or may not be valid
    code.

-   `readOne()`: read the next instruction into the relocator's internal buffer
    and return the number of bytes read so far, including previous calls.
    You may keep calling this method to keep buffering, or immediately call
    either `writeOne()` or `skipOne()`. Or, you can buffer up until the desired
    point and then call `writeAll()`.
    Returns zero when end-of-input is reached, which means the `eoi` property is
    now `true`.

-   `peekNextWriteInsn()`: peek at the next [Instruction](#instruction) to be
    written or skipped

-   `peekNextWriteSource()`: peek at the address of the next instruction to be
    written or skipped

-   `skipOne()`: skip the instruction that would have been written next

-   `skipOneNoLabel()`: skip the instruction that would have been written next,
    but without a label for internal use. This breaks relocation of branches to
    locations inside the relocated range, and is an optimization for use-cases
    where all branches are rewritten (e.g. Frida's Stalker).

-   `writeOne()`: write the next buffered instruction

-   `writeOneNoLabel()`: write the next buffered instruction, but without a
    label for internal use. This breaks relocation of branches to locations
    inside the relocated range, and is an optimization for use-cases where all
    branches are rewritten (e.g. Frida's Stalker).

-   `writeAll()`: write all buffered instructions


## x86 enum types

-   Register: `xax` `xcx` `xdx` `xbx` `xsp` `xbp` `xsi` `xdi` `eax` `ecx` `edx`
    `ebx` `esp` `ebp` `esi` `edi` `rax` `rcx` `rdx` `rbx` `rsp` `rbp` `rsi`
    `rdi` `r8` `r9` `r10` `r11` `r12` `r13` `r14` `r15` `r8d` `r9d` `r10d`
    `r11d` `r12d` `r13d` `r14d` `r15d` `xip` `eip` `rip`
-   InstructionId: `jo` `jno` `jb` `jae` `je` `jne` `jbe` `ja` `js` `jns` `jp`
    `jnp` `jl` `jge` `jle` `jg` `jcxz` `jecxz` `jrcxz`
-   BranchHint: `no-hint` `likely` `unlikely`
-   PointerTarget: `byte` `dword` `qword`


## ArmWriter

+   `new ArmWriter(codeAddress[, { pc: ptr('0x1234') }])`: create a new code
    writer for generating ARM machine code written directly to memory at
    `codeAddress`, specified as a NativePointer.
    The second argument is an optional options object where the initial program
    counter may be specified, which is useful when generating code to a scratch
    buffer. This is essential when using `Memory.patchCode()` on iOS, which may
    provide you with a temporary location that later gets mapped into memory at
    the intended memory location.

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `flush()`: resolve label references and write pending data to memory. You
    should always call this once you've finished generating code. It is usually
    also desirable to do this between pieces of unrelated code, e.g. when
    generating multiple functions in one go.

-   `base`: memory location of the first byte of output, as a NativePointer

-   `code`: memory location of the next byte of output, as a NativePointer

-   `pc`: program counter at the next byte of output, as a NativePointer

-   `offset`: current offset as a JavaScript Number

-   `skip(nBytes)`: skip `nBytes`

-   `putLabel(id)`: put a label at the current position, where `id` is a string
    that may be referenced in past and future `put*Label()` calls

-   `putBImm(target)`: put a B instruction

-   `putBxReg(reg)`: put a BX instruction

-   `putBLabel(labelId)`: put a B instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putLdrRegAddress(reg, address)`: put an LDR instruction

-   `putLdrRegU32(reg, val)`: put an LDR instruction

-   `putAddRegRegImm(dstReg, srcReg, immVal)`: put an ADD instruction

-   `putLdrRegRegImm(dstReg, srcReg, immVal)`: put an LDR instruction

-   `putNop()`: put a NOP instruction

-   `putBreakpoint()`: put an OS/architecture-specific breakpoint instruction

-   `putInstruction(insn)`: put a raw instruction as a JavaScript Number

-   `putBytes(data)`: put raw data from the provided ArrayBuffer


## ArmRelocator

+   `new ArmRelocator(inputCode, output)`: create a new code relocator for
    copying ARM instructions from one memory location to another, taking
    care to adjust position-dependent instructions accordingly.
    The source address is specified by `inputCode`, a NativePointer.
    The destination is given by `output`, an [ArmWriter](#armwriter) pointed
    at the desired target memory address.

-   `reset(inputCode, output)`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `input`: latest [Instruction](#instruction) read so far. Starts out `null`
    and changes on every call to `readOne()`.

-   `eob`: boolean indicating whether end-of-block has been reached, i.e. we've
    reached a branch of any kind, like CALL, JMP, BL, RET.

-   `eoi`: boolean indicating whether end-of-input has been reached, e.g. we've
    reached JMP/B/RET, an instruction after which there may or may not be valid
    code.

-   `readOne()`: read the next instruction into the relocator's internal buffer
    and return the number of bytes read so far, including previous calls.
    You may keep calling this method to keep buffering, or immediately call
    either `writeOne()` or `skipOne()`. Or, you can buffer up until the desired
    point and then call `writeAll()`.
    Returns zero when end-of-input is reached, which means the `eoi` property is
    now `true`.

-   `peekNextWriteInsn()`: peek at the next [Instruction](#instruction) to be
    written or skipped

-   `peekNextWriteSource()`: peek at the address of the next instruction to be
    written or skipped

-   `skipOne()`: skip the instruction that would have been written next

-   `writeOne()`: write the next buffered instruction

-   `writeAll()`: write all buffered instructions


## ThumbWriter

+   `new ThumbWriter(codeAddress[, { pc: ptr('0x1234') }])`: create a new code
    writer for generating ARM machine code written directly to memory at
    `codeAddress`, specified as a NativePointer.
    The second argument is an optional options object where the initial program
    counter may be specified, which is useful when generating code to a scratch
    buffer. This is essential when using `Memory.patchCode()` on iOS, which may
    provide you with a temporary location that later gets mapped into memory at
    the intended memory location.

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `flush()`: resolve label references and write pending data to memory. You
    should always call this once you've finished generating code. It is usually
    also desirable to do this between pieces of unrelated code, e.g. when
    generating multiple functions in one go.

-   `base`: memory location of the first byte of output, as a NativePointer

-   `code`: memory location of the next byte of output, as a NativePointer

-   `pc`: program counter at the next byte of output, as a NativePointer

-   `offset`: current offset as a JavaScript Number

-   `skip(nBytes)`: skip `nBytes`

-   `putLabel(id)`: put a label at the current position, where `id` is a string
    that may be referenced in past and future `put*Label()` calls

-   `putCallAddressWithArguments(func, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putCallRegWithArguments(reg, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putBImm(target)`: put a B instruction

-   `putBLabel(labelId)`: put a B instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putBLabelWide(labelId)`: put a B WIDE instruction

-   `putBxReg(reg)`: put a BX instruction

-   `putBlImm(target)`: put a BL instruction

-   `putBlLabel(labelId)`: put a BL instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putBlxImm(target)`: put a BLX instruction

-   `putBlxReg(reg)`: put a BLX instruction

-   `putCmpRegImm(reg, immValue)`: put a CMP instruction

-   `putBeqLabel(labelId)`: put a BEQ instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putBneLabel(labelId)`: put a BNE instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putBCondLabel(cc, labelId)`: put a B COND instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putBCondLabelWide(cc, labelId)`: put a B COND WIDE instruction

-   `putCbzRegLabel(reg, labelId)`: put a CBZ instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putCbnzRegLabel(reg, labelId)`: put a CBNZ instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putPushRegs(regs)`: put a PUSH instruction with the specified registers,
    specified as a JavaScript array where each element is a string specifying
    the register name.

-   `putPopRegs(regs)`: put a POP instruction with the specified registers,
    specified as a JavaScript array where each element is a string specifying
    the register name.

-   `putLdrRegAddress(reg, address)`: put an LDR instruction

-   `putLdrRegU32(reg, val)`: put an LDR instruction

-   `putLdrRegReg(dstReg, srcReg)`: put an LDR instruction

-   `putLdrRegRegOffset(dstReg, srcReg, srcOffset)`: put an LDR instruction

-   `putStrRegReg(srcReg, dstReg)`: put a STR instruction

-   `putStrRegRegOffset(srcReg, dstReg, dstOffset)`: put a STR instruction

-   `putMovRegReg(dstReg, srcReg)`: put a MOV instruction

-   `putMovRegU8(dstReg, immValue)`: put a MOV instruction

-   `putAddRegImm(dstReg, immValue)`: put an ADD instruction

-   `putAddRegReg(dstReg, srcReg)`: put an ADD instruction

-   `putAddRegRegReg(dstReg, leftReg, rightReg)`: put an ADD instruction

-   `putAddRegRegImm(dstReg, leftReg, rightValue)`: put an ADD instruction

-   `putSubRegImm(dstReg, immValue)`: put a SUB instruction

-   `putSubRegReg(dstReg, srcReg)`: put a SUB instruction

-   `putSubRegRegReg(dstReg, leftReg, rightReg)`: put a SUB instruction

-   `putSubRegRegImm(dstReg, leftReg, rightValue)`: put a SUB instruction

-   `putMrsRegReg(dstReg, srcReg)`: put a MRS instruction

-   `putMsrRegReg(dstReg, srcReg)`: put a MSR instruction

-   `putNop()`: put a NOP instruction

-   `putBkptImm(imm)`: put a BKPT instruction

-   `putBreakpoint()`: put an OS/architecture-specific breakpoint instruction

-   `putInstruction(insn)`: put a raw instruction as a JavaScript Number

-   `putInstructionWide(upper, lower)`: put a raw Thumb-2 instruction from
    two JavaScript Number values

-   `putBytes(data)`: put raw data from the provided ArrayBuffer


## ThumbRelocator

+   `new ThumbRelocator(inputCode, output)`: create a new code relocator for
    copying ARM instructions from one memory location to another, taking
    care to adjust position-dependent instructions accordingly.
    The source address is specified by `inputCode`, a NativePointer.
    The destination is given by `output`, a [ThumbWriter](#thumbwriter) pointed
    at the desired target memory address.

-   `reset(inputCode, output)`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `input`: latest [Instruction](#instruction) read so far. Starts out `null`
    and changes on every call to `readOne()`.

-   `eob`: boolean indicating whether end-of-block has been reached, i.e. we've
    reached a branch of any kind, like CALL, JMP, BL, RET.

-   `eoi`: boolean indicating whether end-of-input has been reached, e.g. we've
    reached JMP/B/RET, an instruction after which there may or may not be valid
    code.

-   `readOne()`: read the next instruction into the relocator's internal buffer
    and return the number of bytes read so far, including previous calls.
    You may keep calling this method to keep buffering, or immediately call
    either `writeOne()` or `skipOne()`. Or, you can buffer up until the desired
    point and then call `writeAll()`.
    Returns zero when end-of-input is reached, which means the `eoi` property is
    now `true`.

-   `peekNextWriteInsn()`: peek at the next [Instruction](#instruction) to be
    written or skipped

-   `peekNextWriteSource()`: peek at the address of the next instruction to be
    written or skipped

-   `skipOne()`: skip the instruction that would have been written next

-   `writeOne()`: write the next buffered instruction

-   `writeAll()`: write all buffered instructions


## ARM enum types

-   Register: `r0` `r1` `r2` `r3` `r4` `r5` `r6` `r7` `r8` `r9` `r10` `r11`
    `r12` `r13` `r14` `r15` `sp` `lr` `sb` `sl` `fp` `ip` `pc`
-   SystemRegister: `apsr_nzcvq`
-   ConditionCode: `eq` `ne` `hs` `lo` `mi` `pl` `vs` `vc` `hi` `ls` `ge` `lt`
    `gt` `le` `al`


## Arm64Writer

+   `new Arm64Writer(codeAddress[, { pc: ptr('0x1234') }])`: create a new code
    writer for generating AArch64 machine code written directly to memory at
    `codeAddress`, specified as a NativePointer.
    The second argument is an optional options object where the initial program
    counter may be specified, which is useful when generating code to a scratch
    buffer. This is essential when using `Memory.patchCode()` on iOS, which may
    provide you with a temporary location that later gets mapped into memory at
    the intended memory location.

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `flush()`: resolve label references and write pending data to memory. You
    should always call this once you've finished generating code. It is usually
    also desirable to do this between pieces of unrelated code, e.g. when
    generating multiple functions in one go.

-   `base`: memory location of the first byte of output, as a NativePointer

-   `code`: memory location of the next byte of output, as a NativePointer

-   `pc`: program counter at the next byte of output, as a NativePointer

-   `offset`: current offset as a JavaScript Number

-   `skip(nBytes)`: skip `nBytes`

-   `putLabel(id)`: put a label at the current position, where `id` is a string
    that may be referenced in past and future `put*Label()` calls

-   `putCallAddressWithArguments(func, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putCallRegWithArguments(reg, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putBranchAddress(address)`: put a BRANCH instruction

-   `putBImm(address)`: put a B instruction

-   `putBLabel(labelId)`: put a B instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putBCondLabel(cc, labelId)`: put a B COND instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putBlImm(address)`: put a BL instruction

-   `putBlLabel(labelId)`: put a BL instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putBrReg(reg)`: put a BR instruction

-   `putBlrReg(reg)`: put a BLR instruction

-   `putRet()`: put a RET instruction

-   `putCbzRegLabel(reg, labelId)`: put a CBZ instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putCbnzRegLabel(reg, labelId)`: put a CBNZ instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putTbzRegImmLabel(reg, bit, labelId)`: put a TBZ instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putTbnzRegImmLabel(reg, bit, labelId)`: put a TBNZ instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putPushRegReg(regA, regB)`: put a PUSH instruction

-   `putPopRegReg(regA, regB)`: put a POP instruction

-   `putPushAllXRegisters()`: put code needed for pushing all X registers on the stack

-   `putPopAllXRegisters()`: put code needed for popping all X registers off the stack

-   `putPushAllQRegisters()`: put code needed for pushing all Q registers on the stack

-   `putPopAllQRegisters()`: put code needed for popping all Q registers off the stack

-   `putLdrRegAddress(reg, address)`: put an LDR instruction

-   `putLdrRegU64(reg, val)`: put an LDR instruction

-   `putLdrRegRef(reg)`: put an LDR instruction with a dangling data reference,
    returning an opaque ref value that should be passed to `putLdrRegValue()`
    at the desired location

-   `putLdrRegValue(ref, value)`: put the value and update the LDR instruction
    from a previous `putLdrRegRef()`

-   `putLdrRegRegOffset(dstReg, srcReg, srcOffset)`: put an LDR instruction

-   `putLdrswRegRegOffset(dstReg, srcReg, srcOffset)`: put an LDRSW instruction

-   `putAdrpRegAddress(reg, address)`: put an ADRP instruction

-   `putStrRegRegOffset(srcReg, dstReg, dstOffset)`: put a STR instruction

-   `putLdpRegRegRegOffset(regA, regB, regSrc, srcOffset, mode)`: put an LDP instruction

-   `putStpRegRegRegOffset(regA, regB, regDst, dstOffset, mode)`: put a STP instruction

-   `putMovRegReg(dstReg, srcReg)`: put a MOV instruction

-   `putUxtwRegReg(dstReg, srcReg)`: put an UXTW instruction

-   `putAddRegRegImm(dstReg, leftReg, rightValue)`: put an ADD instruction

-   `putAddRegRegReg(dstReg, leftReg, rightReg)`: put an ADD instruction

-   `putSubRegRegImm(dstReg, leftReg, rightValue)`: put a SUB instruction

-   `putSubRegRegReg(dstReg, leftReg, rightReg)`: put a SUB instruction

-   `putAndRegRegImm(dstReg, leftReg, rightValue)`: put an AND instruction

-   `putTstRegImm(reg, immValue)`: put a TST instruction

-   `putCmpRegReg(regA, regB)`: put a CMP instruction

-   `putNop()`: put a NOP instruction

-   `putBrkImm(imm)`: put a BRK instruction

-   `putInstruction(insn)`: put a raw instruction as a JavaScript Number

-   `putBytes(data)`: put raw data from the provided ArrayBuffer


## Arm64Relocator

+   `new Arm64Relocator(inputCode, output)`: create a new code relocator for
    copying AArch64 instructions from one memory location to another, taking
    care to adjust position-dependent instructions accordingly.
    The source address is specified by `inputCode`, a NativePointer.
    The destination is given by `output`, an [Arm64Writer](#arm64writer) pointed
    at the desired target memory address.

-   `reset(inputCode, output)`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `input`: latest [Instruction](#instruction) read so far. Starts out `null`
    and changes on every call to `readOne()`.

-   `eob`: boolean indicating whether end-of-block has been reached, i.e. we've
    reached a branch of any kind, like CALL, JMP, BL, RET.

-   `eoi`: boolean indicating whether end-of-input has been reached, e.g. we've
    reached JMP/B/RET, an instruction after which there may or may not be valid
    code.

-   `readOne()`: read the next instruction into the relocator's internal buffer
    and return the number of bytes read so far, including previous calls.
    You may keep calling this method to keep buffering, or immediately call
    either `writeOne()` or `skipOne()`. Or, you can buffer up until the desired
    point and then call `writeAll()`.
    Returns zero when end-of-input is reached, which means the `eoi` property is
    now `true`.

-   `peekNextWriteInsn()`: peek at the next [Instruction](#instruction) to be
    written or skipped

-   `peekNextWriteSource()`: peek at the address of the next instruction to be
    written or skipped

-   `skipOne()`: skip the instruction that would have been written next

-   `writeOne()`: write the next buffered instruction

-   `writeAll()`: write all buffered instructions


## AArch64 enum types

-   Register: `x0` `x1` `x2` `x3` `x4` `x5` `x6` `x7` `x8` `x9` `x10` `x11`
    `x12` `x13` `x14` `x15` `x16` `x17` `x18` `x19` `x20` `x21` `x22` `x23`
    `x24` `x25` `x26` `x27` `x28` `x29` `x30` `w0` `w1` `w2` `w3` `w4` `w5`
    `w6` `w7` `w8` `w9` `w10` `w11` `w12` `w13` `w14` `w15` `w16` `w17` `w18`
    `w19` `w20` `w21` `w22` `w23` `w24` `w25` `w26` `w27` `w28` `w29` `w30`
    `sp` `lr` `fp` `wsp` `wzr` `xzr` `nzcv` `ip0` `ip1` `s0` `s1` `s2` `s3`
    `s4` `s5` `s6` `s7` `s8` `s9` `s10` `s11` `s12` `s13` `s14` `s15` `s16`
    `s17` `s18` `s19` `s20` `s21` `s22` `s23` `s24` `s25` `s26` `s27` `s28`
    `s29` `s30` `s31` `d0` `d1` `d2` `d3` `d4` `d5` `d6` `d7` `d8` `d9` `d10`
    `d11` `d12` `d13` `d14` `d15` `d16` `d17` `d18` `d19` `d20` `d21` `d22`
    `d23` `d24` `d25` `d26` `d27` `d28` `d29` `d30` `d31` `q0` `q1` `q2` `q3`
    `q4` `q5` `q6` `q7` `q8` `q9` `q10` `q11` `q12` `q13` `q14` `q15` `q16`
    `q17` `q18` `q19` `q20` `q21` `q22` `q23` `q24` `q25` `q26` `q27` `q28`
    `q29` `q30` `q31`
-   ConditionCode: `eq` `ne` `hs` `lo` `mi` `pl` `vs` `vc` `hi` `ls` `ge` `lt`
    `gt` `le` `al` `nv`
-   IndexMode: `post-adjust` `signed-offset` `pre-adjust`


## MipsWriter

+   `new MipsWriter(codeAddress[, { pc: ptr('0x1234') }])`: create a new code
    writer for generating MIPS machine code written directly to memory at
    `codeAddress`, specified as a NativePointer.
    The second argument is an optional options object where the initial program
    counter may be specified, which is useful when generating code to a scratch
    buffer. This is essential when using `Memory.patchCode()` on iOS, which may
    provide you with a temporary location that later gets mapped into memory at
    the intended memory location.

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `flush()`: resolve label references and write pending data to memory. You
    should always call this once you've finished generating code. It is usually
    also desirable to do this between pieces of unrelated code, e.g. when
    generating multiple functions in one go.

-   `base`: memory location of the first byte of output, as a NativePointer

-   `code`: memory location of the next byte of output, as a NativePointer

-   `pc`: program counter at the next byte of output, as a NativePointer

-   `offset`: current offset as a JavaScript Number

-   `skip(nBytes)`: skip `nBytes`

-   `putLabel(id)`: put a label at the current position, where `id` is a string
    that may be referenced in past and future `put*Label()` calls

-   `putCallAddressWithArguments(func, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putCallRegWithArguments(reg, args)`: put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value.

-   `putJAddress(address)`: put a J instruction

-   `putJLabel(labelId)`: put a J instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putJrReg(reg)`: put a JR instruction

-   `putJalAddress(address)`: put a JAL instruction

-   `putJalrReg(reg)`: put a JALR instruction

-   `putBOffset(offset)`: put a B instruction

-   `putBeqRegRegLabel(rightReg, leftReg, labelId)`: put a BEQ instruction
    referencing `labelId`, defined by a past or future `putLabel()`

-   `putRet()`: put a RET instruction

-   `putLaRegAddress(reg, address)`: put a LA instruction

-   `putLuiRegImm(reg, imm)`: put a LUI instruction

-   `putOriRegRegImm(rt, rs, imm)`: put an ORI instruction

-   `putLwRegRegOffset(dstReg, srcReg, srcOffset)`: put a LW instruction

-   `putSwRegRegOffset(srcReg, dstReg, dstOffset)`: put a SW instruction

-   `putMoveRegReg(dstReg, srcReg)`: put a MOVE instruction

-   `putAdduRegRegReg(dstReg, leftReg, rightReg)`: put an ADDU instruction

-   `putAddiRegRegImm(destReg, leftReg, imm)`: put an ADDI instruction

-   `putAddiRegImm(destReg, imm)`: put an ADDI instruction

-   `putSubRegRegImm(destReg, leftReg, imm)`: put a SUB instruction

-   `putPushReg(reg)`: put a PUSH instruction

-   `putPopReg(reg)`: put a POP instruction

-   `putMfhiReg(reg)`: put a MFHI instruction

-   `putMfloReg(reg)`: put a MFLO instruction

-   `putMthiReg(reg)`: put a MTHI instruction

-   `putMtloReg(reg)`: put a MTLO instruction

-   `putNop()`: put a NOP instruction

-   `putBreak()`: put a BREAK instruction

-   `putInstruction(insn)`: put a raw instruction as a JavaScript Number

-   `putBytes(data)`: put raw data from the provided ArrayBuffer


## MipsRelocator

+   `new MipsRelocator(inputCode, output)`: create a new code relocator for
    copying MIPS instructions from one memory location to another, taking
    care to adjust position-dependent instructions accordingly.
    The source address is specified by `inputCode`, a NativePointer.
    The destination is given by `output`, a [MipsWriter](#mipswriter) pointed
    at the desired target memory address.

-   `reset(inputCode, output)`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `input`: latest [Instruction](#instruction) read so far. Starts out `null`
    and changes on every call to `readOne()`.

-   `eob`: boolean indicating whether end-of-block has been reached, i.e. we've
    reached a branch of any kind, like CALL, JMP, BL, RET.

-   `eoi`: boolean indicating whether end-of-input has been reached, e.g. we've
    reached JMP/B/RET, an instruction after which there may or may not be valid
    code.

-   `readOne()`: read the next instruction into the relocator's internal buffer
    and return the number of bytes read so far, including previous calls.
    You may keep calling this method to keep buffering, or immediately call
    either `writeOne()` or `skipOne()`. Or, you can buffer up until the desired
    point and then call `writeAll()`.
    Returns zero when end-of-input is reached, which means the `eoi` property is
    now `true`.

-   `peekNextWriteInsn()`: peek at the next [Instruction](#instruction) to be
    written or skipped

-   `peekNextWriteSource()`: peek at the address of the next instruction to be
    written or skipped

-   `skipOne()`: skip the instruction that would have been written next

-   `writeOne()`: write the next buffered instruction

-   `writeAll()`: write all buffered instructions


## MIPS enum types

-   Register: `v0` `v1` `a0` `a1` `a2` `a3` `t0` `t1` `t2` `t3` `t4` `t5` `t6`
    `t7` `s0` `s1` `s2` `s3` `s4` `s5` `s6` `s7` `t8` `t9` `k0` `k1` `gp` `sp`
    `fp` `s8` `ra` `hi` `lo` `zero` `at` `0` `1` `2` `3` `4` `5` `6` `7` `8`
    `9` `10` `11` `12` `13` `14` `15` `16` `17` `18` `19` `20` `21` `22` `23`
    `24` `25` `26` `27` `28` `29` `30` `31`


[r2]: http://radare.org/r/
