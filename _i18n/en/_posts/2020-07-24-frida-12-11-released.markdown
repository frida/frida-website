---
layout: news_item
title: 'Frida 12.11 Released'
date: 2020-07-24 19:00:00 +0200
author: oleavr
version: 12.11
categories: [release]
---

In anticipation of Apple releasing macOS 11, it's time for Frida 12.11! This
release brings full compatibility with macOS 11 Beta 3. Not only that, we now
also support macOS on Apple silicon. Yay!

It's worth noting that we didn't stop at arm64, we also support arm64e. This ABI
is still a moving target, so if you have a Developer Transition Kit (DTK) and
want to take this for a spin you will have to disable SIP, and then add a boot
argument:

{% highlight bash %}
$ sudo nvram boot-args="-arm64e_preview_abi"
{% endhighlight %}

Considering this awesome convergence of platforms, there's actually a chance
that we may already support jailbroken iOS 14. We will know once a public
jailbreak becomes available. At least it shouldn't require much work to support.

So for those of you exploring your DTK, you can grab our CLI tools and Python
bindings the usual way:

{% highlight bash %}
$ pip3 install frida-tools
{% endhighlight %}

As a sidenote we just released [CryptoShark 0.2.0][] and would highly recommend
checking it out. Only caveat is that we only provide binaries for macOS/x86_64
for now, so if you want to try this on macOS/arm64 you will be able to run it
thanks to Rosetta, but attaching to processes on the “Local System” device
won't work.

The workaround is simple though – just grab a frida-server binary from our
[releases][] and fire it up, then point CryptoShark at the “Local Socket”
device. You can also use local SSH port forwarding if you'd like to run
CryptoShark on one system and attach to processes on another:

{% highlight bash %}
$ ssh -L 27042:127.0.0.1:27042 dtk
{% endhighlight %}

There's also a lot of other exciting changes in this release, so definitely
check out the changelog below.

Enjoy!


### Changes in 12.11.0

- Add support for macOS 11 and Apple silicon.
- Daemonize helper process on Darwin. Thanks [@mrmacete][]!
- Daemonize helper process on Linux.
- Fix unreliable iOS device handling when using usbmuxd. Thanks [@mrmacete][]!
- Fix infinite wait when i/macOS frida-helper dies early.
- Add Android spawn() “uid” option to specify user ID. Thanks [@sowdust][]!
- Add support for the latest checkra1n jailbreak. Thanks for the assist,
  [@Hexploitable][]!
- Improve Stalker ARM stability.
- Plug leak in Interceptor arm64 backend error path.
- Fix interception near memcpy() on systems w/o RWX pages.
- Fix encoding of CpuContext pointers on Darwin/arm64e.
- Always strip backtrace items on Darwin/arm64.
- Fix Linux architecture detection on big-endian systems.
- Fix Capstone endianness configuration on ARM BE8.

### Changes in 12.11.1

- Handle i/macOS targets using different ptrauth keys.
- Fix Linux CPU type detection on big-endian systems.
- Fix early instrumentation on Linux/ARM-BE8.
- Fix injection into Linux processes blocked on SIGTTIN or SIGTTOU.

### Changes in 12.11.2

- Fix Stalker thread_exit probing on macOS 11/x86_64.
- Fix slow exports resolution on macOS 11/x86_64.
- Fix CModule support for Capstone headers on ARM.
- Add ArmWriter to the CModule runtime for ARM.
- qml: Add support for specifying the script runtime to use.

### Changes in 12.11.3

- Fix prototype of ModuleMap.values() in the V8 runtime.
- qml: Sync DetachReason enum with the current Frida API.
- qml: Fix Device lifetime logic.

### Changes in 12.11.4

- Fix injector on macOS 11 beta 3. Drop support for older betas.
- Drop helper hack made redundant by macOS 11 beta 3.
- Fix handling of i/macOS introspection modules.

### Changes in 12.11.5

- Fix i/macOS early instrumentation of processes using dyld's modern code path
  on macOS 11 and iOS 14.
- Make JVM method interception safer by installing new methods using
  VMThread::execute(), which blocks all Java threads and makes it safer to do
  interception of hot methods. Thanks [@0xraaz][]!
- Add support for SUB instruction to ARM Relocator. This means improved
  reliability when using Interceptor and Stalker on 32-bit ARM.
- qml: Fix build with GCC by adding missing include.

### Changes in 12.11.6

- Port iOS jailed injector to the new arm64e ABI. This means iOS 14 beta 3 is
  now fully supported in jailed mode, even on A12+ devices.

### Changes in 12.11.7

- Improve libc detection on Linux and QNX. Thanks [@demantz][]!
- Fix checking of symbol sizes in libdwarf backend. This means more reliable
  debug symbol resolution on Linux.
- Fix brittle Android activity start logic. Thanks [@muhzii][]!
- Improve Android Java hooking reliability by clearing the
  *kAccFastInterpreterToInterpreterInvoke* flag. Thanks [@deroko][]!
- Guard against using Java wrappers after *$dispose()*, to make such dangerous
  bugs easier to detect.
- Improve the frida-qml build system and add support for standalone use.

### Changes in 12.11.8

- Add support for macOS 11 beta 4 on Apple silicon.

### Changes in 12.11.9

- Add support for jailed iOS w/ Xcode 12 developer disk images.


[CryptoShark 0.2.0]: https://github.com/frida/cryptoshark/releases/tag/0.2.0
[releases]: https://github.com/frida/frida/releases
[@mrmacete]: https://twitter.com/bezjaje
[@sowdust]: https://github.com/sowdust
[@Hexploitable]: https://twitter.com/Hexploitable
[@0xraaz]: https://twitter.com/0xraaz
[@demantz]: https://github.com/demantz
[@muhzii]: https://github.com/muhzii
[@deroko]: https://github.com/deroko
