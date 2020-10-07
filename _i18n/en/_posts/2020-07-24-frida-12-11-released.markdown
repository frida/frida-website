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

### Changes in 12.11.10

- node: Plug leak in IOStream's WriteOperation. Thanks [@mrmacete][]!
- qml: Add support for listing applications.
- qml: Expose a “count” property on each model.
- Fix ARM relocation of “add sb, pc, r4”.
- Fix ARM relocation of “add ip, pc, #4, #12”.
- Fix ARM writer support for LDMIA when Rn is in reglist.

### Changes in 12.11.11

- Add support for opaque JNI IDs on Android R, to support debuggable apps.
  Thanks [@muhzii][]!
- qml: Add support for spawning processes.
- qml: Add missing libraries when linking with devkit on Linux.
- qml: Fix static linking on Linux.
- qml: Optimize startup to not wait for enumerate_devices().

### Changes in 12.11.12

- Initialize CoreFoundation during early instrumentation on i/macOS. Thanks
  [@mrmacete][]!
- Support a NULL EventSink in Stalker. Thanks [@meme][]!
- node: Provide Electron prebuilds for v10 and v11. Next release will drop
  prebuilds for v9.
- qml: Add post(QJsonArray).

### Changes in 12.11.13

- Fix ART internals probing on Android 11/arm64. Thanks [@enovella_][]!
- Build GumJS runtime for V8 without compression for now, as we need to improve
  frida-compile to use the latest version of [terser][].

### Changes in 12.11.14

- Build GumJS runtime for V8 with compression now that frida-compile has been
  upgraded to the latest version of [terser][].

### Changes in 12.11.15

- Add support for iOS 14.x secure DTX. Thanks [@mrmacete][]!
- Fix Java.deoptimizeEverything() on Android 11. Thanks [@Gh0u1L5][]!

### Changes in 12.11.16

- Fix arm64e support in Arm64Relocator.can_relocate(). Thanks [@mrmacete][]!
- Add “onEvent” option to Stalker.follow(). This allows synchronous
  processing of events in native code – typically implemented using CModule.
  Useful when wanting to implement custom filtering and/or queuing logic to
  improve performance, or sacrifice performance in exchange for reliable event
  delivery.
- Expose Stalker's live CpuContext to EventSink. This can be accessed through
  the “onEvent” callback, and through the Gum C API.
- Add Spinlock to the CModule runtime.

### Changes in 12.11.17

- Kill via LLDB on jailed iOS, to avoid killing via ProcessControl when
  possible. Turns out our previous behavior left debugserver in a bad state
  for which killed apps sometimes would appear as already running, failing early
  instrumentation on subsequent spawn() attempts. Thanks [@mrmacete][]!
- Fix Java bridge initialization on older Android API levels by letting the
  instrumentation field detection fail gracefully. We don't need it on older API
  levels anyway.
- Reduce Duktape memory usage a little per script. There is no need to intern
  the script source code string.

### Changes in 12.11.18

- Skip app extensions when detecting frontmost app on jailed iOS. Sometimes an
  app extension was returned as the first matched process, subsequently throwing
  “Unable to resolve bundle path to bundle ID”. Thanks [@mrmacete][]!
- Improve Android ART instrumentation offset detection for x86/x86_64. Thanks
  [@Gh0u1L5][]!
- Fix JDWP initialization failure on Android 7.1-8.1. Thanks [@Gh0u1L5][]!
- Fix nearest symbol logic in the libdwarf backend.
- Plug a leak in the Duktape-based runtime's argument parsing logic, where any
  collected memory range arrays would leak in case an error occurs parsing one
  of the following arguments.


[CryptoShark 0.2.0]: https://github.com/frida/cryptoshark/releases/tag/0.2.0
[releases]: https://github.com/frida/frida/releases
[@mrmacete]: https://twitter.com/bezjaje
[@sowdust]: https://github.com/sowdust
[@Hexploitable]: https://twitter.com/Hexploitable
[@0xraaz]: https://twitter.com/0xraaz
[@demantz]: https://github.com/demantz
[@muhzii]: https://github.com/muhzii
[@deroko]: https://github.com/deroko
[@meme]: https://github.com/meme
[@enovella_]: https://twitter.com/enovella_
[terser]: https://github.com/terser/terser
[@Gh0u1L5]: https://github.com/Gh0u1L5
