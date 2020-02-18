---
layout: news_item
title: 'Frida 10.0 Released'
date: 2017-05-02 23:00:00 +0200
author: oleavr
version: 10.0
categories: [release]
---

This time we're kicking it up a notch. We're bringing you stability
improvements and state of the art JavaScript support.

Let's talk about the stability improvements first. We fixed a heap
corruption affecting all Linux users. This one was particularly hard to
track down, but [rr][] saved the day. The other issue was a crash on
unload in the Duktape runtime, affecting all OSes.

Dependencies were also upgraded, so as of Frida 10.0.0 you can now enjoy
V8 6.0.124, released just days ago. We also upgraded Duktape to the
latest 2.1.x. The Duktape upgrade resulted in slight changes to the
bytecode semantics, which meant we had to break our API slightly.
Instead of specifying a script's name at load time, it is now specified
when compiling it to bytecode, as this metadata is now included in the
bytecode. This makes a lot more sense, so it was a welcome change.

Beside V8 and Duktape we're also using the latest GLib, Vala compiler,
etc. These upgrades also included JSON-GLib, which recently ditched
autotools in favor of [Meson][]. This is excellent news, as we're also
planning on moving to Meson down the road, so we've now done the
necessary groundwork for making this happen.

So that's about it. This upgrade should not require any changes to
existing code – unless of course you are among the few using the
bytecode API.

Enjoy!

[rr]: http://rr-project.org/
[Meson]: http://mesonbuild.com/
