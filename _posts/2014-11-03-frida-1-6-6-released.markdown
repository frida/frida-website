---
layout: news_item
title: 'Frida 1.6.6 Released'
date: 2014-11-03 14:00:00 +0100
author: oleavr
version: 1.6.6
categories: [release]
---

Tired of waiting for Frida to attach to 32-bit processes on 64-bit Mac
or iOS systems? Or perhaps `frida-trace` takes a while to resolve functions?
If any of the above, or none of it, then this release is for you!

Attaching to 32-bit processes on Mac/iOS hosts has been optimized, and instead
of seconds this is now a matter of milliseconds. That's however specific to
Darwin OSes; this release also speeds up enumeration of module exports on
all OSes. This is now 75% faster, and should be very noticable when using
`frida-trace` and waiting for it to resolve functions.

Also, as an added bonus, teardown while attached to multiple processes no
longer crashes on Darwin and Linux.

Enjoy!
