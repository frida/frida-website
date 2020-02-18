---
layout: news_item
title: 'Frida 7.3 Released'
date: 2016-08-15 23:00:00 +0200
author: oleavr
version: 7.3
categories: [release]
---

It's finally release o'clock, and this time around the focus has been on
improving quality. As it's been a while since the last time we upgraded our
third-party dependencies, and I found myself tracking down a memory-leak in GLib
that had already been fixed upstream, I figured it was time to upgrade our
dependencies. So with this release I'm happy to announce that we're now packing
the latest V8, GLib, Vala compiler, etc. Great care was also taken to eliminate
resource leaks, so you can attach to long-running processes without worrying
about memory allocations or OS handles piling up.

So in closing, let's summarize the changes:

7.3.0:

- core: upgrade to the latest V8, GLib, Vala, Android NDK, etc.
- core: plug resource leaks
- core: fix thread enumeration on Linux/x86-32
- core: (arm64) improve function hooking by adding support for relocating LDRPC
        with an FP/SIMD destination register

7.3.1:

- core: build Android binaries with PIE like we used to

7.3.2:

- core: add *Script.setGlobalAccessHandler()* for handling attempts to access
        undeclared global variables, which is useful for building REPLs

7.3.3:

- objc: convert *Number* to *NSNumber* when an object is expected
- objc: add support for auto-converting to an array of objects, useful when
        calling e.g. *+[NSArray arrayWithObjects:count:]*

7.3.4:

- core: improve the unstable accessor API
- core: fix the Duktape globals accessor logic so it's only applied to reads

7.3.5:

- core: improve *hexdump()* to support any *NativePointer*-conforming object
- objc: fix handling of the *L* type

7.3.6:

- core: fix regression in devkit header auto-generation logic

Enjoy!
