---
layout: news_item
title: 'Frida 1.0.11 Released'
date: 2014-03-09 19:00:00 +0100
author: oleavr
version: 1.0.11
categories: [release]
---

Some of you experienced issues injecting into processes on Windows, as well as
crashes on iOS. Here's a new release bringing some serious improvements to
Frida's internals:

-   V8 has been upgraded to 3.25 in order to fix the iOS stability issues. This
    also means new features (like ECMAScript 6) and improved performance on all
    platforms. Another nice aspect is that Frida now depends on a V8 version
    that runs on 64-bit ARM, which paves the way for porting Frida itself to
    AArch64.
-   The Windows injector has learned some new tricks and will get you into even
    more processes. A configuration error was also discovered in the Windows
    build system, which explains why some of you were unable to inject into
    some processes.
-   For those of you building Frida on Windows, the build system there now
    depends on VS2013. This means XP is no longer supported, though it is still
    possible to build with the `v120_xp` toolchain if any of you still depend
    on that, so let me know if this is a deal-breaker for you.
-   The recently added support for `this.lastError` (Windows) is now working
    correctly.

That's all for now. Let us know what you think, and if you like Frida, please
help spread the word! :)
