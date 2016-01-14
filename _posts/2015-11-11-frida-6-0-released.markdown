---
layout: news_item
title: 'Frida 6.0 Released'
date: 2015-11-11 19:00:00 +0100
author: oleavr
version: 6.0
categories: [release]
---

Epic release this time, with brand new iOS 9 support and improvements all over
the place. For some more background, check out my blog posts [here](https://www.nowsecure.com/blog/2015/11/16/ios-9-reverse-engineering-with-javascript/)
and [here](https://www.nowsecure.com/blog/2015/11/23/ios-instrumentation-without-jailbreak/).

There's a lot of ground to cover here, but the summary is basically:

6.0.0:

- core: add support for OS X El Capitan
- core: add support for iOS 9
- core: fix launchd plist permissions in Cydia package
- core: disable our dynamic linker on iOS for now
- core: add new JavaScript runtime based on JavaScriptCore, as we cannot
        use V8 on iOS 9 with the current jailbreak
- core: add brand new system session when attaching to *pid=0*
- core: improve arm hooking, including support for early TBZ/TBNZ/IT/B.cond,
        and avoid relocating instructions that a later instruction loops back to
- core: fix relocation of LDR.W instructions on arm64
- core: abort when we're stuck in an exception loop
- core: fix *AutoIgnorer*-related deadlocks
- core: drop our *.* prefix so temporary files are easier to discover
- python: add support for running without ES6 support
- python: tweak setup.py to allow offline installation
- python: lock the prompt-toolkit version to 0.38 for now
- frida-repl: fix display of raw buffers as returned by *Memory.readByteArray()*
- frida-repl: fix crash in completion on error
- node: add support for DeviceManager's *added* and *removed* signals
- node: add example showing how to watch available devices
- node: use prebuild instead of node-pre-gyp
- node: Babelify the source code read by *frida.load()*
- node: remove *frida.load()* as it's now in the frida-load module

6.0.1:

- python: stop providing 3.4 binaries and move to 3.5 instead
- node: fix Linux linking issue where we fail to pick up our libffi
- node: also produce prebuild for Node.js LTS

6.0.2:

- core: provide FridaGadget.dylib for instrumenting iOS apps without jailbreak
- core: add support for the iOS Simulator
- core: improve *MemoryAccessMonitor* to allow monitoring any combination of
        R, W or X operations on a page
- python: fix UTF-8 fields being accidentally exposed as *str* on Python 2.x

6.0.3:

- core: fix *spawn()* on OS X

6.0.4:

- core: add partial support for using the gadget standalone
- CLI tools: fix crash when the stdout encoding cannot represent all characters
- frida-trace: always treat handler scripts as UTF-8

6.0.5:

- core: add logical shift right and left operations to NativePointer
- core: improve Interceptor to support attaching to a replaced function
- core: add support for hooking tiny functions on 32-bit ARM
- core: emulate *{Get/Set}LastErrror* and TLS key access on Windows, allowing
        us to hook more low-level APIs

6.0.6:

- core: fix launchd / Jetsam issue on iOS 9
- core: fix iOS 9 code signing issue
- core: update security attributes on named pipe to allow us to inject into
        more Windows apps

6.0.7:

- core: add support for injecting into processes on linux-arm
- core: fix crashes related to the DebugSymbol API on Mac and iOS
- frida-trace: improve manpage parser

6.0.8:

- core: fix Linux compatibility issue caused by failing to link libstdc++
        statically

6.0.9:

- core: add support for running frida-gadget standalone
- core: add a temporary workaround for Windows compatibility regression
- core: port the Fruity backend to Linux, allowing direct access to connected
        iOS devices
- core: expose the InvocationContext *context* read-write in the JavaScriptCore
        runtime also
- core: fix issue with InvocationContext's CpuContext getting GCed prematurely

6.0.10:

Re-release of 6.0.9 with a Windows build regression fix.

6.0.11:

- core: prevent stale HostSession objects in case of network errors
- CLI tools: assume UTF-8 when the stdout encoding is unknown
- node: fix double free caused by using the wrong Nan API

6.0.12:

- core: update security attributes on named pipe on Windows
- core: add CreateProcessW flags to prevent IFEO loop on Windows
- core: fix hooking of recursive functions on arm and arm64
- python: fix Python 3 line endings regression
- node: update prebuild dependency

Enjoy!
