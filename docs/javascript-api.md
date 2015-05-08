---
layout: docs
title: JavaScript API
prev_section: ios
next_section: troubleshooting
permalink: /docs/javascript-api/
---

## Table of contents
  1. [Global](#global)
  * [console](#console)
  * [Frida](#frida)
  * [Process](#process)
  * [Module](#module)
  * [Memory](#memory)
  * [MemoryAccessMonitor](#memoryaccessmonitor)
  * [Thread](#thread)
  * [NativePointer](#nativepointer)
  * [NativeFunction](#nativefunction)
  * [NativeCallback](#nativecallback)
  * [Socket](#socket)
  * [File](#file)
  * [Interceptor](#interceptor)
  * [Stalker](#stalker)
  * [Instruction](#instruction)
  * [ObjC](#objc)
  * [Dalvik](#dalvik)
  * [WeakRef](#weakref)

## Global

+   `ptr(s)`: short-hand for `new NativePointer(s)`

+   `NULL`: short-hand for `ptr("0")`

+   `recv([type, ]callback)`: request `callback` to be called on the next
    message received from your Frida-based application. Optionally `type` may
    be specified to only receive a message where the `type` field is set to
    `type`.

    This will only give you one message, so you need to call `recv()` again
    to receive the next one.

+   `send(message[, data])`: send the JavaScript object `message` to your
    Frida-based application (it must be serializable to JSON). `data` may be
    optionally passed to include a raw payload, like a buffer returned by
    `Memory#readByteArray`.

+   `setTimeout(fn, delay)`: call `fn` after `delay` milliseconds. Returns an
    id that can be passed to `clearTimeout` to cancel it.

+   `clearTimeout(id)`: cancel id returned by call to `setTimeout`

+   `setInterval(fn, delay)`: call `fn` every `delay` milliseconds. Returns an
    id that can be passed to `clearInterval` to cancel it.

+   `clearInterval(id)`: cancel id returned by call to `setInterval`


## console

+   `console.log(line)`: write `line` to the console of your Frida-based
    application. The exact behavior depends on where
    [frida-core](https://github.com/frida/frida-core) is integrated.
    For example, this output goes to *stdout* when using Frida through
    [frida-python](https://github.com/frida/frida-python),
    [qDebug](http://doc.qt.io/qt-5/qdebug.html) when using
    [frida-qml](https://github.com/frida/frida-qml), etc.

## Frida

+   `Frida.version`: property containing the current Frida version

## Process

+   `Process.arch`: property containing the string `ia32`, `x64`, `arm`
    or `arm64`

+   `Process.platform`: property containing the string `windows`,
    `darwin`, `linux` or `qnx`

+   `Process.pointerSize`: property containing the size of a pointer
    (in bytes) as a JavaScript number. This is used to make your scripts more
    portable.

+   `Process.isDebuggerAttached()`: returns a boolean indicating whether a
    debugger is currently attached

+   `Process.getCurrentThreadId()`: get this thread's OS-specific id as a
    JavaScript number

+   `Process.enumerateThreads(callbacks)`: enumerate threads alive right now,
    where `callbacks` is an object specifying:

    -   `onMatch: function onMatch(thread)`: called with `thread` object
        containing:
        -   `id`: OS-specific id
        -   `state`: string specifying either `running`, `stopped`, `waiting`,
            `uninterruptible` or `halted`
        -   `context`: object with the keys `pc` and `sp`, which are
            NativePointer objects specifying EIP/RIP/PC and ESP/RSP/SP,
            respectively, for ia32/x64/arm. Other processor-specific keys
            are also available, e.g. `eax`, `rax`, `r0`, `x0`, etc.

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function onComplete()`: called when all threads have been
        enumerated

+   `Process.enumerateThreadsSync()`: synchronous version of
    `enumerateThreads()` that returns the threads in an array.

+   `Process.enumerateModules(callbacks)`: enumerate modules loaded right now,
    where `callbacks` is an object specifying:

    -   `onMatch: function onMatch(module)`: called with `module` object
        containing:
        -   `name`: canonical module name as a string
        -   `base`: base address as a `NativePointer`
        -   `size`: size in bytes
        -   `path`: full filesystem path as a string

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function onComplete()`: called when all modules have been
        enumerated

+   `Process.enumerateModulesSync()`: synchronous version of
    `enumerateModules()` that returns the modules in an array.

+   `Process.enumerateRanges(protection, callbacks)`: enumerate memory ranges
    satisfying `protection` given as a string of the form: `rwx`, where `rw-`
    means "must be at least readable and writable". `callbacks` is an object
    specifying:

    -   `onMatch: function onMatch(range)`: called with `range` object
        containing:
        -   `base`: base address as a `NativePointer`
        -   `size`: size in bytes
        -   `protection`: protection string (see above)

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function onComplete()`: called when all memory ranges have
        been enumerated

+   `Process.enumerateRangesSync(protection)`: synchronous version of
    `enumerateRanges()` that returns the ranges in an array.


## Module

+   `Module.enumerateExports(name, callbacks)`: enumerate exports of module with
    the `name` as seen in `Process#enumerateModules`. `callbacks` is an object
    specifying:

    -   `onMatch: function onMatch(mod)`: called with `mod` object containing:
        -   `type`: string specifying either `function` or `variable`
        -   `name`: export name as a string
        -   `address`: absolute address as a `NativePointer`

        This function may return the string `stop` to cancel the enumeration
        early.

    -   `onComplete: function onComplete()`: called when all exports have been
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

+   `Module.findExportByName(module, exp)`: returns the absolute address of the
    export named `exp` in `module`


## Memory

+   `Memory.scan(address, size, pattern, callbacks)`: scan memory for
    occurences of `pattern` in the memory range given by `address` and `size`.

    -   `pattern` must be of the form "13 37 ?? ff" to match 0x13 followed by
        0x37 followed by any byte followed by 0xff

    -   `callbacks` is an object with:

        -   `onMatch: function onMatch(address, size)`: called with `address`
            containing the address of the occurence as a `NativePointer` and
            `size` specifying the size as a JavaScript number.

            This function may return the string `stop` to cancel the memory
            scanning early.

        -   `onError: function onError(reason)`: called with `reason` when
            there was a memory access error while scanning

        -   `onComplete: function onComplete()`: called when the memory range
            has been fully scanned

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
    `Memory.readS64(address)`, `Memory.readU64(address)`:
    read a signed or unsigned 8/16/32/64-bit value from `address` and return it
    as a JavaScript number.

    A JavaScript exception will be thrown if `address` isn't readable.

+   `Memory.writeS8(address, value)`, `Memory.writeU8(address, value)`,
    `Memory.writeS16(address, value)`, `Memory.writeU16(address, value)`,
    `Memory.writeS32(address, value)`, `Memory.writeU32(address, value)`,
    `Memory.writeS64(address, value)`, `Memory.writeU64(address, value)`:
    write the JavaScript number `value` to the signed or unsigned 8/16/32/64-bit
    value at `address`.

    A JavaScript exception will be thrown if `address` isn't writable.

+   `Memory.readByteArray(address, length)`: read `length` bytes from `address`
    and return it as a byte array. This byte array may be efficiently
    transferred to your Frida-based application by passing it as the second
    argument to `send()`.

    A JavaScript exception will be thrown if any of the `length` bytes read from
    `address` isn't readable.

+   `Memory.writeByteArray(address, bytes)`: write the `bytes` byte array to
    `address`. This is either an object returned from `Memory.readByteArray()`
    or a JavaScript array-style object. For example: `[ 0x13, 0x37, 0x42 ]`.

    A JavaScript exception will be thrown if any of the bytes written to
    `address` isn't writable.

+   `Memory.readCString(address[, size = -1])`,
    `Memory.readUtf8String(address[, size = -1])`,
    `Memory.readUtf16String(address[, size = -1])`,
    `Memory.readAnsiString(address[, size = -1])`:
    read the bytes at `address` as an ASCII, UTF-8, UTF-16 or ANSI string.
    Supply the optional `size` argument if you know the size of the string
    in bytes, or omit it or specify -1 if the string is NUL-terminated.

    A JavaScript exception will be thrown if any of the `size` bytes read from
    `address` isn't readable.

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

    -   `onAccess: function onAccess(details)`: called synchronously with
        `details` object containing:
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


## NativePointer

+   `new NativePointer(s)`: create a new NativePointer from the string `s`
    containing a memory address in either decimal, or hexadecimal if prefixed
    with "0x". You may use the `ptr(s)` short-hand for brevity.

-   `isNull()`: returns a boolean allowing you to conveniently check if a
    pointer is NULL

-   `add(rhs)`: make a new NativePointer with this NativePointer plus `rhs`.
    `rhs` may either be a JavaScript number or another NativePointer.

-   `sub(rhs)`: make a new NativePointer with this NativePointer minus `rhs`.
    `rhs` may either be a JavaScript number or another NativePointer.

-   `toInt32()`: cast this NativePointer to a signed 32-bit integer

-   `toString([radix = 16])`: convert to a string of optional radix (defaults to
    16)


## NativeFunction

+   `new NativeFunction(address, returnType, argTypes[, abi])`: create a new
    NativeFunction to call the function at `address` (specified with a
    `NativePointer`), where the `returnType` string specifies the return type,
    and the `argTypes` array specifies the argument types. You may optionally
    also specify `abi` if not system default. For variadic functions, add a
    `'...'` entry to `argTypes` between the fixed arguments and the variadic
    ones.
    Note that the returned object is also a `NativePointer`, and can thus be
    passed to `Interceptor#attach`.

    Supported types:

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

    Supported ABIs:

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
    NativeCallback implemented by the JavaScript function `func`, where the
    `returnType` string specifies the return type, and the `argTypes` array
    specifies the argument types. You may also specify the abi if not system
    default. See `NativeFunction` for details about supported types and abis.
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


## File

+   `new File(filePath, mode)`: open or create the file at `filePath` with
    the `mode` string specifying how it should be opened. For example `"wb"`
    to open the file for writing in binary mode (this is the same format as
    `fopen()` from the C standard library).

-   `write(data)`: synchronously write `data` to the file, where `data` is
    either a string or a buffer as returned by `Memory#readByteArray`

-   `flush()`: flush any buffered data to the underlying file

-   `close()`: close the file. You should call this function when you're done
    with the file.


## Interceptor

+   `Interceptor.attach(target, callbacks)`: intercept calls to function at
    `target`. This is a `NativePointer` specifying the address of the function
    you would like to intercept calls to. Note that on 32-bit ARM this address
    must have its least significant bit set to 0 for ARM functions, and 1 for
    Thumb functions. Frida takes care of this detail for you if you get the
    address from a Frida API (for example `Module.findExportByName()`).

    The `callbacks` argument is an object containing one or more of:

    -   `onEnter: function onEnter(args)`: callback function given one argument
        `args` that can be used to read or write arguments as an array of
        `NativePointer` objects.

    -   `onLeave: function onLeave(retval)`: callback function given one
        argument `retval` that is a `NativePointer` containing the return
        value. You may call `retval.replace(1337)` to replace the return value
        with the integer `1337`, or `retval.replace(ptr("0x1234"))` to replace
        with a pointer.

    Note that these functions will be invoked with `this` bound to a
    per-invocation (thread-local) object where you can store arbitrary data,
    which is useful if you want to read an argument in `onEnter` and act on it
    in `onLeave`.

    For example:

{% highlight js %}
Interceptor.attach(Module.findExportByName("libc.so", "read"), {
    onEnter: function onEnter(args) {
        this.fileDescriptor = args[0].toInt32();
    },
    onLeave: function onLeave(retval) {
        if (retval.toInt32() > 0) {
            /* do something with this.fileDescriptor */
        }
    }
});
{% endhighlight %}

    Additionally, the object contains some useful properties:

    -   `context`: object with the keys `pc` and `sp`, which are
        NativePointer objects specifying EIP/RIP/PC and ESP/RSP/SP,
        respectively, for ia32/x64/arm. Other processor-specific keys
        are also available, e.g. `eax`, `rax`, `r0`, `x0`, etc.
        You may also update register values by assigning to these keys.

    -   `errno`: (UNIX) current errno value (you may replace it)

    -   `lastError`: (Windows) current OS error value (you may replace it)

    -   `threadId`: OS thread ID

    -   `depth`: call depth of relative to other invocations

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
  onReceive: function onReceive(events) {
    // Called with `events` containing a binary blob which is one or more
    // GumEvent structs.  See `gumevent.h` for the format. This is obviously a
    // terrible API that is subject to change once a better trade-off between
    // ease-of-use and performance has been found.
  },
  onCallSummary: function onCallSummary(summary) {
    // Called with `summary` being a key-value mapping of call target to number
    // of calls, in the current time window. You would typically implement this
    // instead of `onReceive` for efficiency.
  }
});
{% endhighlight %}

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

+   `ObjC.classes`: an object mapping class names to `ObjC.Object` JavaScript
    bindings for each of the currently registered classes.

{% highlight js %}
var UIAlertView = ObjC.classes.UIAlertView; /* iOS */
var view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
    "Frida",
    "Hello from Frida",
    NULL,
    "OK",
    NULL);
view.show();
view.release();
{% endhighlight %}

+   `ObjC.mainQueue`: the GCD queue of the main thread

+   `ObjC.schedule(queue, work)`: schedule the JavaScript function `work` on
    the GCD queue specified by `queue`. An `NSAutoreleasePool` is created just
    before calling `work`, and cleaned up on return.

{% highlight js %}
var NSSound = ObjC.classes.NSSound; /* Mac */
ObjC.schedule(ObjC.mainQueue, function () {
    var sound = NSSound.alloc().initWithContentsOfFile_byReference_("/Users/oleavr/.Trash/test.mp3", true);
    sound.play();
});
{% endhighlight %}

+   `new ObjC.Object(handle)`: create a JavaScript binding given the existing
    object at `handle` (a NativePointer).

{% highlight js %}
var sound = new ObjC.Object(ptr("0x1234"));
{% endhighlight %}

+   `ObjC.implement(method, fn)`: create a JavaScript implementation compatible
    with the signature of `method`, where the JavaScript function `fn` is used
    as the implementation. Returns a `NativeCallback` that you may assign to an
    ObjC method's `implementation` property.

{% highlight js %}
var NSSound = ObjC.classes.NSSound; /* Mac */
var oldImpl = NSSound.play.implementation;
NSSound.play.implementation = ObjC.implement(NSSound.play, function (handle, selector) {
    return oldImpl(handle, selector);
});

var NSView = ObjC.classes.NSView; /* Mac */
var drawRect = NSView['- drawRect:'];
var oldImpl = drawRect.implementation;
drawRect.implementation = ObjC.implement(drawRect, function (handle, selector) {
    oldImpl(handle, selector);
});
{% endhighlight %}

>   As the `implementation` property is a `NativeFunction` and thus also a
>   `NativePointer`, you may also use `Interceptor` to hook functions:

{% highlight js %}
var NSSound = ObjC.classes.NSSound; /* Mac */
Interceptor.attach(NSSound.play.implementation, {
    onEnter: function onEnter() {
        send("[NSSound play]");
    }
});
{% endhighlight %}

+   `ObjC.selector(name)`: convert the JavaScript string `name` to a selector

+   `ObjC.selectorAsString(sel)`: convert the selector `sel` to a JavaScript
    string


## Dalvik

+   `Dalvik.available`: a boolean specifying whether the current process has the
    Dalvik VM loaded. Do not invoke any other `Dalvik` properties or methods
    unless this is the case.

+   `Dalvik.perform(fn)`: ensure that the current thread is attached to the VM
    and call `fn`. (This isn't necessary in callbacks from Java.)

{% highlight js %}
Dalvik.perform(function () {
    var Activity = Dalvik.use("android.app.Activity");
    Activity.onResume.implementation = function () {
        send("onResume() got called! Let's call the original implementation");
        this.onResume();
    };
});
{% endhighlight %}

+   `Dalvik.use(className)`: dynamically get a JavaScript wrapper for
    `className` that you can instantiate objects from by calling `$new()` on
    it to invoke a constructor. Call `$dispose()` on an instance to clean it
    up explicitly (or wait for the JavaScript object to get garbage-collected,
    or script to get unloaded). Static and non-static methods are available,
    and you can even replace a method implementation and throw an exception
    from it:

{% highlight js %}
Dalvik.perform(function () {
    var Activity = Dalvik.use("android.app.Activity");
    var Exception = Dalvik.use("java.lang.Exception");
    Activity.onResume.implementation = function () {
        throw Exception.$new("Oh noes!");
    };
});
{% endhighlight %}

+   `Dalvik.cast(handle, klass)`: create a JavaScript wrapper given the existing
    instance at `handle` of given class `klass` (as returned from
    `Dalvik.use()`).

{% highlight js %}
var Activity = Dalvik.use("android.app.Activity");
var activity = Dalvik.cast(ptr("0x1234"), Activity);
{% endhighlight %}


## WeakRef

+   `WeakRef.bind(value, fn)`: monitor `value` and call the `fn` callback as
    soon as `value` has been garbage-collected, or the script is about to get
    unloaded. Returns an id that you can pass to `WeakRef.unbind()` for
    explicit cleanup.

    This API is useful if you're building a language-binding, where you need to
    free native resources when a JS value is no longer needed.

+   `WeakRef.unbind(id)`: stop monitoring the value passed to
    `WeakRef.bind(value, fn)`, and call the `fn` callback immediately.
