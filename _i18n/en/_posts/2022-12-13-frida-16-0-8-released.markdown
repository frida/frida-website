---
layout: news_item
title: 'Frida 16.0.8 Released'
date: 2022-12-13 00:21:38 +0100
author: oleavr
version: 16.0.8
categories: [release]
---

This time we've focused on polishing up our macOS and iOS support. For those of
you using *spawn()* and spawn-gating for early instrumentation, things are now
in much better shape.

## i/macOS spawn() performance

The most exciting change in this release is all about performance. Programs that
would previously take a while to start when launched using Frida should now be a
lot quicker to start. This long-standing bottleneck was so bad that an app with
a lot of libraries could fail to launch due to Frida slowing down its startup
too much.

## i/macOS and SIGPIPE

Next up we have a fix for a long-standing reliability issue. Turns out our
file-descriptors used for IPC did not have SO_NOSIGPIPE set, so we could
sometimes end up in a situation where either Frida or the target process
terminated abruptly, and the other side would end up getting zapped by SIGPIPE
while trying to write().

## Sandboxed environments, part two

The previous release introduced some bold new changes to support injecting into
hardened targets. Since then [@hsorbo][] and me dug back into our recent GLib
kqueue() patch and fixed some rough edges. We also fixed a regression where
attaching to hardened processes through usbmuxd would fail with “connection
closed”.

## Linux

On the Linux and Android side of things, some of you may have noticed that
thread enumeration could fail randomly, especially inside busy processes. That
issue has now finally been dealt with.

Also, thanks to [@drosseau][] we also have an error-handling improvement that
should avoid some confusion when things fail in 32-/64-bit cross-arch builds.

## EOF

That is all this time around. Enjoy!


[@hsorbo]: https://twitter.com/hsorbo
[@drosseau]: https://github.com/drosseau
