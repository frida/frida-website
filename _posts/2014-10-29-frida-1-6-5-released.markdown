---
layout: news_item
title: 'Frida 1.6.5 Released'
date: 2014-10-29 23:00:00 +0100
author: oleavr
version: 1.6.5
categories: [release]
---

It's release o'clock, and time for some bugfixes:

- iOS 8.1 is now supported, and the ARM64 support is better than ever.
- The iOS USB transport no longer disconnects when sending a burst of data to
  the device. This would typically happen when using `frida-trace` and tracing
  a bunch of functions, resulting in a burst of data being sent over the wire.
  This was actually [a generic networking issue affecting Mac and iOS](https://bugzilla.gnome.org/show_bug.cgi?id=11059),
  but was very reproducible when using Frida with a tethered iOS device.
- Eliminated crashes on shutdown of the Python interpreter.
- The `onEnter` and `onLeave` callbacks in `frida-trace` scripts are now called
  with `this` bound to the correct object, which means that it's bound to an
  object specific to that thread and invocation, and not an object shared by
  all threads and invocations.
