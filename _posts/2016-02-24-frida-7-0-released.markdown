---
layout: news_item
title: 'Frida 7.0 Released'
date: 2016-02-24 04:00:00 +0100
author: oleavr
version: 7.0
categories: [release]
---

It's been a while since our last major release bump. This time we're addressing
the long-standing issue where 64-bit integers were represented as JavaScript
Number values. This meant that values beyond 53 bits were problematic due to
the fact that the underlying representation is a double.

The 64-bit types in the *Memory*, *NativeFunction*, and *NativeCallback* APIs
are now properly represented by the newly introduced [Int64](/docs/javascript-api/#int64)
and [UInt64](/docs/javascript-api/#uint64) types, and their APIs are almost
identical to [NativePointer](/docs/javascript-api/#nativepointer).

Now let's cross our fingers that int64/uint64 [make it into ES7](https://twitter.com/BrendanEich/status/526826278377099264).

So in closing, here's a summary of the changes:

7.0.0:

- core: rework handling of 64-bit integers
- core: improve strictness of constructors
- core: improve QNX support
- frida-repl: update the logo

7.0.1:

- core: fix Int64/UInt64 field capacity on 32-bit architectures

7.0.2:

- core: allow Int64 and UInt64 to be passed as-is to all relevant APIs
- core: fix handling of $protocols on ObjC instances

7.0.3:

- core: fix race-condition where listener gets destroyed mid-call
- core: fix handling of nested native exception scopes
- core: improve QNX support
- frida-repl: tweak the startup message

7.0.4:

- core: massively improve the function hooking success-rate on 32-bit ARM
- core: improve the function hooking success-rate on 64-bit ARM
- core: fix the *sp* value exposed by Interceptor on 32-bit ARM

7.0.5:

- core: spin the main CFRunLoop while waiting for *Device#resume()* when
        spawning iOS apps, allowing thread-sensitive early instrumentation to be
        applied from the main thread

7.0.6:

- core: fix hooking of half-word aligned functions on 32-bit ARM
- core: fix thread enumeration on Linux
- core: add simple *hexdump()* API to the Script runtimes
- core: make the Duktape runtime's CpuContext serializable to JSON

7.0.7:

- core: allow passing a *NativePointer* to *hexdump()*

7.0.8:

- core: fix handling of wrapper objects in `retval.replace()`
- core: fix behavior of Memory.readUtf8String() when a size is specified
- core: add support for the new *task_for_pid(0)* method on the iOS 9.1 JB
- core: don't use *cbnz* which is not available in ARM mode on some processors
- core: implement *enumerate_threads()* and *modify_thread()* for QNX

7.0.9:

- core: fix early crash in FridaGadget.dylib on iOS when running with
        *ios-deploy* and other environments where we are loaded before
        *CoreFoundation*
- core: run a *CFRunLoop* in the main thread of *frida-helper* on Darwin,
        allowing system session scripts to make use of even more Apple APIs
- core: add stream APIs for working with GIO streams, for now only exposed
        through UnixInputStream and UnixOutputStream (UNIX), and
        Win32InputStream and Win32OutputStream (Windows)

Enjoy!
