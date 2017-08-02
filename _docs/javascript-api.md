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
  1. [Process](#process)
  1. [Module](#module)
  1. [Memory](#memory)
  1. [MemoryAccessMonitor](#memoryaccessmonitor)
  1. [Thread](#thread)
  1. [Int64](#int64)
  1. [UInt64](#uint64)
  1. [NativePointer](#nativepointer)
  1. [NativeFunction](#nativefunction)
  1. [NativeCallback](#nativecallback)
  1. [Socket](#socket)
  1. [Stream](#stream)
  1. [File](#file)
  1. [Interceptor](#interceptor)
  1. [Stalker](#stalker)
  1. [ApiResolver](#apiresolver)
  1. [DebugSymbol](#debugsymbol)
  1. [Instruction](#instruction)
  1. [ObjC](#objc)
  1. [Java](#java)
  1. [WeakRef](#weakref)

## Global

+   `hexdump(target[, options])`: generate a hexdump from the provided
    *ArrayBuffer* or *NativePointer* `target`, optionally with `options` for
    customizing the output.

    For example:

{% highlight js %}
var libc = Module.findBaseAddress('libc.so');
var buf = Memory.readByteArray(libc, 64);
console.log(hexdump(buf, {
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
    some memory using `Memory#readByteArray`, then you may pass this through the
    optional `data` argument. This requires it to either be an ArrayBuffer or an
    array of integers between 0 and 255.

<div class="note">
  <h5>Performance considerations</h5>
  <p>
    While <i>send()</i> is asynchronous, the total overhead of sending a single
    message is not optimized for high frequencies, so that means Frida leaves
    it up to you to batch multiple values into a single <i>send()</i>-call,
    based on whether low delay or high throughput is desired.
  </p>
</div>

+   `setTimeout(fn, delay)`: call `fn` after `delay` milliseconds. Returns an
    id that can be passed to `clearTimeout` to cancel it.

+   `clearTimeout(id)`: cancel id returned by call to `setTimeout`

+   `setInterval(fn, delay)`: call `fn` every `delay` milliseconds. Returns an
    id that can be passed to `clearInterval` to cancel it.

+   `clearInterval(id)`: cancel id returned by call to `setInterval`


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
        return new Promise(resolve => {
            setTimeout(() => {
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

const co = require('co');
const frida = require('frida');
const load = require('frida-load');

let session, script;
co(function *() {
    const source = yield load(require.resolve('./agent.js'));
    session = yield frida.attach("iTunes");
    script = yield session.createScript(source);
    script.events.listen('message', onMessage);
    yield script.load();
    const api = yield script.getExports();
    console.log(yield api.add(2, 3));
    console.log(yield api.sub(5, 3));
})
.catch(onError);

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

+   `Frida.version`: property containing the current Frida version


## Process

+   `Process.arch`: property containing the string `ia32`, `x64`, `arm`
    or `arm64`

+   `Process.platform`: property containing the string `windows`,
    `darwin`, `linux` or `qnx`

+   `Process.pageSize`: property containing the size of a virtual memory page
    (in bytes) as a JavaScript number. This is used to make your scripts more
    portable.

+   `Process.pointerSize`: property containing the size of a pointer
    (in bytes) as a JavaScript number. This is used to make your scripts more
    portable.

+   `Process.isDebuggerAttached()`: returns a boolean indicating whether a
    debugger is currently attached

+   `Process.getCurrentThreadId()`: get this thread's OS-specific id as a
    JavaScript number

+   `Process.enumerateThreads(callbacks)`: enumerate all threads,
    where `callbacks` is an object specifying:

    -   `onMatch: function (thread)`: called with `thread` object containing:
        -   `id`: OS-specific id
        -   `state`: string specifying either `running`, `stopped`, `waiting`,
            `uninterruptible` or `halted`
        -   `context`: object with the keys `pc` and `sp`, which are
            NativePointer objects specifying EIP/RIP/PC and ESP/RSP/SP,
            respectively, for ia32/x64/arm. Other processor-specific keys
            are also available, e.g. `eax`, `rax`, `r0`, `x0`, etc.

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function ()`: called when all threads have been enumerated

+   `Process.enumerateThreadsSync()`: synchronous version of
    `enumerateThreads()` that returns the threads in an array.

+   `Process.findModuleByAddress(address)`,
    `Process.getModuleByAddress(address)`,
    `Process.findModuleByName(name)`,
    `Process.getModuleByName(name)`:
    return an object with details about the module whose *address* or *name*
    matches the one specified. In the event that no such module could be found,
    the *find*-prefixed functions return *null* whilst the *get*-prefixed
    functions throw an exception.  See `Process.enumerateModules()` for
    details about which fields are included.

+   `Process.enumerateModules(callbacks)`: enumerate modules loaded right now,
    where `callbacks` is an object specifying:

    -   `onMatch: function (module)`: called with `module` object containing:
        -   `name`: canonical module name as a string
        -   `base`: base address as a `NativePointer`
        -   `size`: size in bytes
        -   `path`: full filesystem path as a string

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function ()`: called when all modules have been enumerated

+   `Process.enumerateModulesSync()`: synchronous version of
    `enumerateModules()` that returns the modules in an array.

+   `Process.findRangeByAddress(address)`, `getRangeByAddress(address)`:
    return an object with details about the range containing *address*. In the
    event that no such range could be found, *findRangeByAddress()* returns
    *null* whilst *getRangeByAddress()* throws an exception.  See
    `Process.enumerateRanges()` for details about which fields are included.

+   `Process.enumerateRanges(protection|specifier, callbacks)`: enumerate memory
    ranges satisfying `protection` given as a string of the form: `rwx`, where
    `rw-` means "must be at least readable and writable". Alternatively you may
    provide a `specifier` object with a `protection` key whose value is as
    aforementioned, and a `coalesce` key set to `true` if you'd like neighboring
    ranges with the same protection to be coalesced (the default is `false`;
    i.e. keeping the ranges separate). `callbacks` is an object specifying:

    -   `onMatch: function (range)`: called with `range` object containing:
        -   `base`: base address as a `NativePointer`
        -   `size`: size in bytes
        -   `protection`: protection string (see above)
        -   `file`: (when available) file mapping details as an object
            containing:

            -   `path`: full filesystem path as a string
            -   `offset`: offset in bytes

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function ()`: called when all memory ranges have been
        enumerated

+   `Process.enumerateRangesSync(protection|specifier)`: synchronous version of
    `enumerateRanges()` that returns the ranges in an array.

+   `Process.enumerateMallocRanges(callbacks)`: just like `enumerateRanges()`,
    but for individual memory allocations known to the system heap.

+   `Process.enumerateMallocRangesSync(protection)`: synchronous version of
    `enumerateMallocRanges()` that returns the ranges in an array.


## Module

+   `Module.enumerateImports(name, callbacks)`: enumerate imports of module with
    the `name` as seen in `Process#enumerateModules`. `callbacks` is an object
    specifying:

    -   `onMatch: function (imp)`: called with `imp` object containing:
        -   `type`: string specifying either `function` or `variable`
        -   `name`: import name as a string
        -   `module`: module name as a string
        -   `address`: absolute address as a `NativePointer`

        Only the `name` field is guaranteed to be present for all imports. The
        platform-specific backend will do its best to resolve the other fields
        even beyond what the native metadata provides, but there is no guarantee
        that it will succeed.  This function may return the string `stop` to
        cancel the enumeration early.

    -   `onComplete: function ()`: called when all imports have been
        enumerated

+   `Module.enumerateImportsSync(name)`: synchronous version of
    `enumerateImports()` that returns the imports in an array.

+   `Module.enumerateExports(name, callbacks)`: enumerate exports of module with
    the `name` as seen in `Process#enumerateModules`. `callbacks` is an object
    specifying:

    -   `onMatch: function (exp)`: called with `exp` object containing:
        -   `type`: string specifying either `function` or `variable`
        -   `name`: export name as a string
        -   `address`: absolute address as a `NativePointer`

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function ()`: called when all exports have been
        enumerated

+   `Module.enumerateExportsSync(name)`: synchronous version of
    `enumerateExports()` that returns the exports in an array.

+   `Module.enumerateRanges(name, protection, callbacks)`: just like
    `Process#enumerateRanges`, except it's scoped to the specified module
    `name`.

+   `Module.enumerateRangesSync(name, protection)`: synchronous version of
    `enumerateRanges()` that returns the ranges in an array.

+   `Module.findBaseAddress(name)`: returns the base address of the `name`
    module, or `null` if the module isn't loaded

+   `Module.findExportByName(module|null, exp)`: returns the absolute address of
    the export named `exp` in `module`. If the module isn't known you may pass
    `null` instead of its name, but this can be a costly search and should be
    avoided.


## Memory

+   `Memory.scan(address, size, pattern, callbacks)`: scan memory for
    occurences of `pattern` in the memory range given by `address` and `size`.

    -   `pattern` must be of the form "13 37 ?? ff" to match 0x13 followed by
        0x37 followed by any byte followed by 0xff

    -   `callbacks` is an object with:

        -   `onMatch: function (address, size)`: called with `address`
            containing the address of the occurence as a `NativePointer` and
            `size` specifying the size as a JavaScript number.

            This function may return the string `stop` to cancel the memory
            scanning early.

        -   `onError: function (reason)`: called with `reason` when there was a
            memory access error while scanning

        -   `onComplete: function ()`: called when the memory range has been
            fully scanned

-   `Memory.scanSync(address, size, pattern)`: synchronous version of `scan()`
    that returns the matches in an array.

+   `Memory.alloc(size)`: allocate `size` bytes of memory on the heap. The
    returned object is a `NativePointer` and the heap memory will be released
    when all JavaScript handles to it are gone. This means you need to keep
    a reference to it while the pointer is being used by code outside the
    JavaScript runtime.

+   `Memory.copy(dst, src, n)`: just like memcpy.

+   `Memory.dup(address, size)`: short-hand for `Memory.alloc()` followed by
    `Memory.copy()`.

+   `Memory.protect(address, size, protection)`: update protection on a region
    of memory, where `protection` is a string of the same format as
    `Process.enumerateRanges()`.

    For example:

{% highlight js %}
Memory.protect(ptr("0x1234"), 4096, 'rw-');
{% endhighlight %}

+   `Memory.readPointer(address)`: read a pointer from `address` and return
    it as a `NativePointer`.

    A JavaScript exception will be thrown if `address` isn't readable.

+   `Memory.writePointer(address, ptr)`: write `ptr` to `address`.

    A JavaScript exception will be thrown if `address` isn't writable.

+   `Memory.readS8(address)`, `Memory.readU8(address)`,
    `Memory.readS16(address)`, `Memory.readU16(address)`,
    `Memory.readS32(address)`, `Memory.readU32(address)`,
    `Memory.readShort(address)`, `Memory.readUShort(address)`,
    `Memory.readInt(address)`, `Memory.readUInt(address)`,
    `Memory.readFloat(address)`, `Memory.readDouble(address)`:
    read a signed or unsigned 8/16/32/etc. or float/double value from
    `address` and return it as a JavaScript number.

    A JavaScript exception will be thrown if `address` isn't readable.

+   `Memory.writeS8(address, value)`, `Memory.writeU8(address, value)`,
    `Memory.writeS16(address, value)`, `Memory.writeU16(address, value)`,
    `Memory.writeS32(address, value)`, `Memory.writeU32(address, value)`,
    `Memory.writeShort(address, value)`, `Memory.writeUShort(address, value)`,
    `Memory.writeInt(address, value)`, `Memory.writeUInt(address, value)`,
    `Memory.writeFloat(address, value)`, `Memory.writeDouble(address, value)`:
    write the JavaScript number `value` to the signed or unsigned
    8/16/32/etc. or float/double value at `address`.

    A JavaScript exception will be thrown if `address` isn't writable.

+   `Memory.readS64(address)`, `Memory.readU64(address)`,
    `Memory.readLong(address)`, `Memory.readULong(address):
    read a signed or unsigned 64-bit, or long-sized, value from `address` and
    return it as an Int64/UInt64 object.

    A JavaScript exception will be thrown if `address` isn't readable.

+   `Memory.writeS64(address, value)`, `Memory.writeU64(address, value)`,
    `Memory.writeLong(address, value)`, `Memory.writeULong(address, value)`:
    write the Int64/UInt64 `value` to the signed or unsigned 64-bit, or
    long-sized, value at `address`.

    A JavaScript exception will be thrown if `address` isn't writable.

+   `Memory.readByteArray(address, length)`: read `length` bytes from `address`
    and return it as an ArrayBuffer. This buffer may be efficiently transferred
    to your Frida-based application by passing it as the second argument to
    `send()`.

    A JavaScript exception will be thrown if any of the `length` bytes read from
    `address` isn't readable.

+   `Memory.writeByteArray(address, bytes)`: write `bytes` to `address`, where
    the former is either an ArrayBuffer, typically returned from
    `Memory.readByteArray()`, or an array of integers between 0 and 255. For
    example: `[ 0x13, 0x37, 0x42 ]`.

    A JavaScript exception will be thrown if any of the bytes written to
    `address` isn't writable.

+   `Memory.readCString(address[, size = -1])`,
    `Memory.readUtf8String(address[, size = -1])`,
    `Memory.readUtf16String(address[, length = -1])`,
    `Memory.readAnsiString(address[, size = -1])`:
    read the bytes at `address` as an ASCII, UTF-8, UTF-16 or ANSI string.
    Supply the optional `size` argument if you know the size of the string
    in bytes, or omit it or specify -1 if the string is NUL-terminated.
    Likewise you may supply the optional `length` argument if you know the
    length of the string in characters.

    A JavaScript exception will be thrown if any of the `size` / `length` bytes
    read from `address` isn't readable.

    Note that `readAnsiString()` is only available (and relevant) on Windows.

+   `Memory.writeUtf8String(address, str)`,
    `Memory.writeUtf16String(address, str)`,
    `Memory.writeAnsiString(address, str)`:
    encode and write the JavaScript string to `address` (with NUL-terminator).

    A JavaScript exception will be thrown if any of the bytes written to
    `address` isn't writable.

    Note that `writeAnsiString()` is only available (and relevant) on Windows.

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
            string specifying either `read`, `write` or `execute`
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
var f = Module.findExportByName("libcommonCrypto.dylib",
    "CCCryptorCreate");
Interceptor.attach(f, {
    onEnter: function (args) {
        console.log("CCCryptorCreate called from:\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n") + "\n");
    }
});
{% endhighlight %}

+   `Thread.sleep(delay)`: suspend execution of the current thread for `delay`
    seconds specified as a JavaScript number. For example 0.05 to sleep for
    50 ms.


## Int64

+   `new Int64(v)`: create a new Int64 from `v`, which is either a JavaScript
    Number or a string containing a value in decimal, or hexadecimal if prefixed
    with "0x". You may use the `int64(v)` short-hand for brevity.

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    make a new Int64 with this Int64 plus/minus/and/or/xor `rhs`, which may
    either be a JavaScript number or another Int64

-   `shr(n)`, `shl(n)`:
    make a new Int64 with this Int64 shifted right/left by `n` bits

-   `compare(rhs)`: returns an integer comparison result just like
    String#localeCompare()

-   `toNumber()`: cast this Int64 to a JavaScript Number

-   `toString([radix = 10])`: convert to a string of optional radix (defaults to
    10)


## UInt64

+   `new UInt64(v)`: create a new UInt64 from `v`, which is either a JavaScript
    Number or a string containing a value in decimal, or hexadecimal if prefixed
    with "0x". You may use the `uint64(v)` short-hand for brevity.

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    make a new UInt64 with this UInt64 plus/minus/and/or/xor `rhs`, which may
    either be a JavaScript number or another UInt64

-   `shr(n)`, `shl(n)`:
    make a new UInt64 with this UInt64 shifted right/left by `n` bits

-   `compare(rhs)`: returns an integer comparison result just like
    String#localeCompare()

-   `toNumber()`: cast this UInt64 to a JavaScript Number

-   `toString([radix = 10])`: convert to a string of optional radix (defaults to
    10)


## NativePointer

+   `new NativePointer(s)`: create a new NativePointer from the string `s`
    containing a memory address in either decimal, or hexadecimal if prefixed
    with "0x". You may use the `ptr(s)` short-hand for brevity.

-   `isNull()`: returns a boolean allowing you to conveniently check if a
    pointer is NULL

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    make a new NativePointer with this NativePointer plus/minus/and/or/xor
    `rhs`, which may either be a JavaScript number or another NativePointer

-   `shr(n)`, `shl(n)`:
    make a new NativePointer with this NativePointer shifted right/left by `n`
    bits

-   `equals(rhs)`: returns a boolean indicating whether `rhs` is equal to
    this one; i.e. it has the same pointer value

-   `compare(rhs)`: returns an integer comparison result just like
    String#localeCompare()

-   `toInt32()`: cast this NativePointer to a signed 32-bit integer

-   `toString([radix = 16])`: convert to a string of optional radix (defaults to
    16)

-   `toMatchPattern()`: returns a string containing a `Memory.scan()`-compatible
    match pattern for this pointer's raw value


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


## NativeCallback

+   `new NativeCallback(func, returnType, argTypes[, abi])`: create a new
    NativeCallback implemented by the JavaScript function `func`, where
    `returnType` specifies the return type, and the `argTypes` array specifies
    the argument types. You may also specify the abi if not system default.
    See `NativeFunction` for details about supported types and abis.
    Note that the returned object is also a `NativePointer`, and can thus be
    passed to `Interceptor#replace`.


## Socket

+   `Socket.type(handle)`: inspect the OS socket `handle` and return its type
    as a string which is either `tcp`, `udp`, `tcp6`, `udp6`, `unix:stream`,
    `unix:dgram`, or `null` if invalid or unknown.

+   `Socket.localAddress(handle)`,
    `Socket.peerAddress(handle)`:
    inspect the OS socket `handle` and return its local or peer address, or
    `null` if invalid or unknown.

    The object returned has the fields:

    -   `ip`: (IP sockets) IP address as a string.
    -   `port`: (IP sockets) Port number as a JavaScript number.
    -   `path`: (UNIX sockets) UNIX path as a string.


## Stream

+   `new UnixInputStream(fd[, options])`,
    `new UnixOutputStream(fd[, options])`,
    `new Win32InputStream(handle[, options])`,
    `new Win32OutputStream(handle[, options])`: create a new stream object
    from the file descriptor `fd` (UNIX) or file *HANDLE* `handle` (Windows).
    You may also supply an `options` object with `autoClose` set to `true` to
    make the stream close the underlying OS resource when the stream is
    released, either through `close()` or future garbage-collection.

    All methods of the returned object are fully asynchronous and return a
    *Promise* object.

-   `close()`: close the stream, releasing resources related to it. Once the
    stream is closed, all other operations will fail. Closing a stream multiple
    times is allowed and will not result in an error.

-   `InputStream#read(size)`: read up to `size` bytes from the stream. The
    returned *Promise* receives an *ArrayBuffer* up to `size` bytes long. End of
    stream is signalled through an empty buffer.

-   `InputStream#readAll(size)`: keep reading from the stream until exactly
    `size` bytes have been consumed. The returned *Promise* receives an
    *ArrayBuffer* that is exactly `size` bytes long. Premature error or end of
    stream results in the *Promise* getting rejected with an error, where the
    `Error` object has a `partialData` property containing the incomplete data.

-   `OutputStream#write(data)`: try to write `data` to the stream. The `data`
    value is either an *ArrayBuffer* or an array of integers between 0 and 255.
    The returned *Promise* receives a *Number* specifying how many bytes of
    `data` were written to the stream.

-   `OutputStream#writeAll(data)`: keep writing to the stream until all of
    `data` has been written. The `data` value is either an *ArrayBuffer* or an
    array of integers between 0 and 255. Premature error or end of stream
    results in an error, where the `Error` object has a `partialSize` property
    specifying how many bytes of `data` were written to the stream before the
    error occurred.


## File

+   `new File(filePath, mode)`: open or create the file at `filePath` with
    the `mode` string specifying how it should be opened. For example `"wb"`
    to open the file for writing in binary mode (this is the same format as
    `fopen()` from the C standard library).

-   `write(data)`: synchronously write `data` to the file, where `data` is
    either a string or a buffer as returned by `Memory#readByteArray`

-   `flush()`: flush any buffered data to the underlying file

-   `close()`: close the file. You should call this function when you're done
    with the file. Any remaining buffered data will automatically be flushed
    before closure.


## Interceptor

+   `Interceptor.attach(target, callbacks)`: intercept calls to function at
    `target`. This is a `NativePointer` specifying the address of the function
    you would like to intercept calls to. Note that on 32-bit ARM this address
    must have its least significant bit set to 0 for ARM functions, and 1 for
    Thumb functions. Frida takes care of this detail for you if you get the
    address from a Frida API (for example `Module.findExportByName()`).

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
Interceptor.attach(Module.findExportByName("libc.so", "read"), {
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
var openPtr = Module.findExportByName("libc.so", "open");
var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
Interceptor.replace(openPtr, new NativeCallback(function (pathPtr, flags) {
    var path = Memory.readUtf8String(pathPtr);
    log("Opening '" + path + "'");
    var fd = open(pathPtr, flags);
    log("Got fd: " + fd);
    return fd;
}, 'int', ['pointer', 'int']));
{% endhighlight %}

+   `Interceptor.revert(target)`: revert function at `target` to the previous
    implementation.


## Stalker

+   `Stalker.follow([threadId, options])`: start stalking `threadId` (or the
    current thread if omitted), optionally with `options` for enabling events.

    For example:

{% highlight js %}
Stalker.follow(Process.getCurrentThreadId(), {
  events: {
    call: true, // CALL instructions: yes please
    ret: false, // RET instructions: no thanks
    exec: false // all instructions: no thanks
  },
  onReceive: function (events) {
    // Called with `events` containing a binary blob which is one or more
    // GumEvent structs.  See `gumevent.h` for the format. This is obviously a
    // terrible API that is subject to change once a better trade-off between
    // ease-of-use and performance has been found.
  },
  onCallSummary: function (summary) {
    // Called with `summary` being a key-value mapping of call target to number
    // of calls, in the current time window. You would typically implement this
    // instead of `onReceive` for efficiency.
  }
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

+   `Stalker.garbageCollect()`: free accumulated memory at a safe point after
    `Stalker#unfollow`. This is needed to avoid race-conditions where the
    thread just unfollowed is executing its last instructions.

+   `Stalker.addCallProbe(address, callback)`: call `callback` (see
    `Interceptor#attach#onEnter` for signature) synchronously when a CALL is
    made to `address`. Returns an id that can be passed to
    `Stalker#removeCallProbe` later.

+   Stalker.removeCallProbe: remove a call probe added by
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

-   `enumerateMatches(query, callbacks)`: perform the resolver-specific `query`
    string, where `callbacks` is an object specifying:

    -   `onMatch: function (match)`: called for each match, where `match` is an
        object with `name` and `address` keys.

    -   `onComplete: function ()`: called when all matches have been enumerated.

{% highlight js %}
var resolver = new ApiResolver('module');
resolver.enumerateMatches('exports:*!open*', {
  onMatch: function (match) {
    /*
     * Where `match` contains an object like this one:
     *
     * {
     *     name: '/usr/lib/libSystem.B.dylib!opendir$INODE64',
     *     address: ptr('0x7fff870135c9')
     * }
     */
  },
  onComplete: function () {
  }
});
{% endhighlight %}

{% highlight js %}
var resolver = new ApiResolver('objc');
resolver.enumerateMatches('-[NSURL* *HTTP*]', {
  onMatch: function (match) {
    /*
     * Where `match` contains an object like this one:
     *
     * {
     *     name: '-[NSURLRequest valueForHTTPHeaderField:]',
     *     address: ptr('0x7fff94183e22')
     * }
     */
  },
  onComplete: function () {
  }
});
{% endhighlight %}

-   `enumerateMatchesSync(query)`: synchronous version of `enumerateMatches()`
    that returns the matches in an array.


## DebugSymbol

+   `DebugSymbol.fromAddress(address)`, `DebugSymbol.fromName(name)`:
    look up debug information for `address`/`name` and return it as an object
    containing:

    -   `address`: Address that this symbol is for, as a `NativePointer`.
    -   `name`: Name of the symbol, as a string.
    -   `moduleName`: Module name owning this symbol, as a string.
    -   `fileName`: File name owning this symbol, as a string.
    -   `lineNumber`: Line number in `fileName`, as a JavaScript number.

    You may also call `toString()` on it, which is very useful when combined
    with `Thread.backtrace()`:

{% highlight js %}
var f = Module.findExportByName("libcommonCrypto.dylib",
    "CCCryptorCreate");
Interceptor.attach(f, {
    onEnter: function (args) {
        console.log("CCCryptorCreate called from:\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n") + "\n");
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
    example `Module.findExportByName()`).

    The object returned has the fields:

    -   `address`: Address (EIP) of this instruction, as a `NativePointer`.
    -   `next`: Pointer to the next instruction, so you can `parse()` it.
    -   `size`: Size of this instruction.
    -   `mnemonic`: String representation of instruction mnemonic.
    -   `opStr`: String representation of instruction operands.
    -   `toString()`: Convert to a human-readable string.


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

+   `Java.enumerateLoadedClasses(callbacks)`: enumerate classes loaded right
    now, where `callbacks` is an object specifying:

    -   `onMatch: function (className)`: called for each loaded class with
        `className` that may be passed to `use()` to get a JavaScript wrapper.

    -   `onComplete: function ()`: called when all classes have been enumerated.

+   `Java.enumerateLoadedClassesSync()`: synchronous version of
    `enumerateLoadedClasses()` that returns the class names in an array.

+   `Java.perform(fn)`: ensure that the current thread is attached to the VM
    and call `fn`. (This isn't necessary in callbacks from Java.)

{% highlight js %}
Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    Activity.onResume.implementation = function () {
        send("onResume() got called! Let's call the original implementation");
        this.onResume();
    };
});
{% endhighlight %}

**Note:** In case you are using on an older version of Frida (for whatsoever reasons), early instrumentation may still be achieved using `Java.performNow()` instead of `Java.perform()`

Below is a working sample using Java.performNow(): In the below example we are trying to hook into a popular Java crypto library, *java.security.KeyPair*, and get hold of the privateKey when it gets generated. 

{% highlight js %}
Java.performNow(
  function()
  {
    var item = Java.use("java.security.KeyPair"); 
    console.log("the PrivateKey class was just loaded");
    item.getPrivate.implementation = function()
    {
      console.log("[*] This got called ");
      var ret = this.getPrivate();
      console.log("[*] Private key is " + ret);
      return ret;
    }
  }
);
{% endhighlight %}

+   `Java.use(className)`: dynamically get a JavaScript wrapper for
    `className` that you can instantiate objects from by calling `$new()` on
    it to invoke a constructor. Call `$dispose()` on an instance to clean it
    up explicitly (or wait for the JavaScript object to get garbage-collected,
    or script to get unloaded). Static and non-static methods are available,
    and you can even replace a method implementation and throw an exception
    from it:

{% highlight js %}
Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    var Exception = Java.use("java.lang.Exception");
    Activity.onResume.implementation = function () {
        throw Exception.$new("Oh noes!");
    };
});
{% endhighlight %}

+   `Java.scheduleOnMainThread(fn)`: run `fn` on the main thread of the VM.

+   `Java.choose(className, callbacks)`: enumerate live instances of the
    `className` class by scanning the Java heap, where `callbacks` is an
    object specifying:

    -   `onMatch: function (instance)`: called once for each live instance found
        with a ready-to-use `instance` just as if you would have called
        `Java.cast()` with a raw handle to this particular instance.

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function ()`: called when all instances have been enumerated

+   `Java.cast(handle, klass)`: create a JavaScript wrapper given the existing
    instance at `handle` of given class `klass` (as returned from
    `Java.use()`). Such a wrapper also has a `class` property for getting a
    wrapper for its class, and a `$className` property for getting a string
    representation of its class-name.

{% highlight js %}
var Activity = Java.use("android.app.Activity");
var activity = Java.cast(ptr("0x1234"), Activity);
{% endhighlight %}

**Note** Difference between Java.use() and Java.choose() 

*use () :*
Doest not give direct access to the objects at all. 
Gives access to the object via the `this` operator.

Let's take this as an example :

{% highlight js %}
Java.perform(function () {
    var Activity = Java.use("gca.lc");
    Activity.methodM1.overload('[B', 'java.lang.String').implementation = function (a, str) {
        var retval = this.methodM1(a, str);
        console.log("[*] return value4: "+retval);
        return retval;
    };
    });
{% endhighlight %}

So in the above we are saying that :
Give me a javascript wrapper for the class `lc` in the package `gca`. This is being referenced by `Activity` in our case. Now we say that whenever the method, `methodM1`, from `gca.lc` (which in this case also happens to be overloaded) gets called by any object (or from anywhere in the app), hook it and run my javascript function as defined above. Inside this javascript function, I am using the `this` operator to call methodM1 explicitly with the current object (which we have access to through the `this` operator). 

Note that we can actually create a new object of `gca.lc` (using the `$new()`) because I have reference of the class. I can also access the current object also using the `this` operator. However, all of this can happen only when the method, `methodM1`, of `gca.lc` gets called. 

So `Java.use` comes into play only when the app makes an object of the given class **AND** (the word `AND` is of utmost importance here) the method, `methodM1`, gets called then I can take control of the object etc. 

Now imagine a real life situation wherein say `gca.lc` has a method, `m2`, which actually deals with some super secret stuff. Now m2 gets called only based on certain conditions and there is no way to simulate those conditions. Now if we were using Java.use as above, because the app itself (or we) are never even able to meet those conditions, we would never be able to get access to the object at all, nor do anything with it, because all of it depends on the method `m2` being called in the first place. 

This is where `Java.choose()` comes to the rescue. With `Java.choose()` we say that whenever the object gets made, irrespective of what methods are being called in the app etc. simply give me access to the object being made itself. That's why here we also have to provide the callback, saying as soon as the object is formed, make a call back to my callback() and do whatever I say in there. 

## WeakRef

+   `WeakRef.bind(value, fn)`: monitor `value` and call the `fn` callback as
    soon as `value` has been garbage-collected, or the script is about to get
    unloaded. Returns an id that you can pass to `WeakRef.unbind()` for
    explicit cleanup.

    This API is useful if you're building a language-binding, where you need to
    free native resources when a JS value is no longer needed.

+   `WeakRef.unbind(id)`: stop monitoring the value passed to
    `WeakRef.bind(value, fn)`, and call the `fn` callback immediately.
