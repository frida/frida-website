---
layout: news_item
title: 'Frida 5.0 Released'
date: 2015-09-17 19:00:00 +0100
author: oleavr
version: 5.0
categories: [release]
---

Wow, another major release! We decided to change the Device API to give you
persistent IDs so you can easily tell different devices apart as they're
hotplugged.

But that's just the beginning of it, we're also bringing a ton of other
improvements this time:

5.0.0:

- core: change Device.id to represent individual devices across reconnects
- core: add new Droidy backend for interfacing with connected Android devices
- core: adjust confusing iPhone 5+ device name on Darwin
- core: normalize the fallback iOS device name for consistency with Android
- core: upgrade V8 to 4.5.103.30
- objc: include both class and instance methods in *$methods* and *$ownMethods*
- python: add -D switch for specifying the device id to connect to
- python: add frida-ls-devices CLI tool for listing devices
- python: update to the new Device.id API
- python: add *get_local_device()* and improve API consistency with frida-node
- node: update to the new Device.id API
- node: improve the top-level facade API
- qml: update to the new Device.id API
- clr: update to the new Device.id API
- frida-ps: improve the output formatting

5.0.1:

- core: add support for source maps
- node: add frida.load() for turning a CommonJS module into a script
- node: upgrade Nan

5.0.2:

- core: add *console.warn()* and *console.error()*
- core: add *Module.enumerateImports()* and implement on Darwin, Linux,
        and Windows
- core: allow *null* module name when calling *Module.findExportByName()*
- core: move *Darwin.Module* and *Darwin.Mapper* from frida-core to frida-gum,
        allowing easy Mach-O parsing and out-of-process dynamic linking
- core: better handling of temporary files
- frida-trace: add support for conveniently tracing imported functions
- frida-trace: blacklist dyld_stub_binder from being traced
- python: avoid logging getting overwritten by the status message changing

5.0.3:

- core: improve arm64 hooking, including support for hooking short functions

5.0.4:

- core: improve arm64 hooking, also taking care to avoid relocating instructions
        that other instructions depend on, including the next instruction after
        a BL/BLR/SVC instruction
- core: port *Arm64Writer* and *Arm64Relocator* to Capstone

5.0.5:

- core: fix crash on teardown by using new API provided by our GLib patch
- core: fix module name resolving on Linux
- core: improve ELF handling to also consider *ET_EXEC* images as valid modules
- core: improve arm64 hooking
- core: port *{Arm,Thumb}Writer* and *{Arm,Thumb}Relocator* to Capstone
- python: fix tests on OS X 10.11
- node: fix tests on OS X 10.11

5.0.6:

- core: turn NativeFunction invocation crash into a JS exception when possible
- core: add *Process.setExceptionHandler()* for handling native exceptions from
        JS
- core: install a default exception handler that emits error messages
- core: prevent apps from overriding our exception handler if we install ours
        early in the process life-time
- core: gracefully handle it if we cannot replace native functions
- core: allow RPC exports to return ArrayBuffer values
- python: add support for rpc methods returning ArrayBuffer objects
- node: add support for rpc methods returning ArrayBuffer objects

5.0.7:

- core: don't install a default exception handler for now

5.0.8:

Re-release of 5.0.7 due to build machine issues.

5.0.9:

- python: update setup.py to match new build server configuration

5.0.10:

- core: fix instrumentation of arm64 functions with early usage of IP registers

Enjoy!
