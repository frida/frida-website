---
layout: news_item
title: 'Frida 2.0.0 Released'
date: 2015-03-01 01:00:00 +0100
author: oleavr
version: 2.0.0
categories: [release]
---

It's time for a new and exciting release! Key changes include:

- No more kernel panics on Mac and iOS! Read the full story
  [here](https://medium.com/@oleavr/diy-kernel-panic-os-x-and-ios-in-10-loc-c250d9649159).
- Mac and iOS injector performs manual mapping of Frida's dylib. This means
  we're able to attach to heavily sandboxed processes.
- The CLI tools like *frida-trace*, *frida-repl*, etc., have brand new support
  for spawning processes:
{% highlight bash %}
$ frida-trace -i 'open*' -i 'read*' /bin/cat /etc/resolv.conf
    27 ms	open$NOCANCEL()
    28 ms	read$NOCANCEL()
    28 ms	read$NOCANCEL()
    28 ms	read$NOCANCEL()
Target process terminated.
Stopping...
$
{% endhighlight %}
- Usability improvements in *frida-repl* and *frida-discover*.
- First call to `DeviceManager.enumerate_devices()` does a better job and
  also gives you the currently connected iOS devices, so for simple applications
  or scripts you no longer have to subscribe to updates if you require the
  device to already be present.
- The python API now provides you with `frida.get_usb_device(timeout = 0)` and
  `frida.get_remote_device()` for easy access to iOS and remote/Android
  devices.
- The `onEnter` and `onLeave` callbacks passed to `Interceptor.attach()` may
  access `this.registers` to inspect CPU registers, which is really useful
  when dealing with custom calling conventions.
- `console.log()` logs to the console on your application's side instead of
  the target process. This change is actually why we had to bump the major
  version for this release.
- Android 5.0 compatibility, modulo ART support.
- Brand new support for Android/x86. Everything works except the Dalvik
  integration; please get in touch if you'd like to help out with a pull-request
  to fix that!

Want to help out? Have a look at our [GSoC 2015 Ideas Page](https://www.frida.re/docs/gsoc-ideas-2015/)
to get an overview of where we'd like to go next.

Enjoy!

**Update 2am:** An iOS issue slipped through the final testing, so we
just pushed 2.0.1 to remedy this.

**Update 11pm:** Thanks to your excellent feedback we found a critical
bug when using Frida on Windows with certain iOS device configurations.
Please upgrade to 2.0.2 and let us know if you run into any issues.
