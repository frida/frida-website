---
layout: news_item
title: 'Frida 12.9 Released'
date: 2020-05-19 22:00:00 +0200
author: oleavr
version: 12.9
categories: [release]
---

Our previous big release was all about [Stalker][]. For those of you not yet
familiar with it, it's basically a code tracing engine – allowing threads to be
followed, capturing every function, every block, even every instruction which is
executed. Beyond just tracing code, it also allows you to add and remove
instructions anywhere. It even uses advanced JIT tricks to make all of this
really fast.

That may still sound a little abstract, so let's have a look at a couple of
examples. One way to use it is when you want to determine “[what other functions
does this function call][]”. Or, perhaps you'd like to use Apple's speech
synthesizer to announce the RAX register's value at every RET instruction in
code belonging to the app? [Here][] is how that can be done. This was one of the
demos at my [r2con presentation][] back in 2017.

Up until now Stalker has only been available on Intel architectures and ARM64.
So I'm really excited to announce that Stalker is now also available on ARM32!
Yay! 🎉 I'm hopeful that this sorely missed Stalker backend will motivate a lot
of you to start building really cool things on top of Stalker. I feel like it
has a ton of potential beyond “just” code tracing. And combined with [CModule][]
it's become really easy to balance rapid prototyping and dynamic behavior with
performance.

There's so much to talk about in this release. One of the other major changes is
that we have upgraded all of our dependencies. Most interesting among them is
probably V8, which we have upgraded to 8.4. This means you can use all of the
latest JavaScript language features such as [optional chaining][] and [nullish
coalescing operator][] without having to [frida-compile][] your agent. That, and
performance improvements, another area where V8 just keeps on getting better and
better.

We've also just added support for Android 11 Developer Preview 4, and iOS/arm64e
apps are now fully supported even on jailed iOS. Things have improved so much
across all of our supported platforms. One thing in particular that I'd like to
highlight is that we have finally eliminated a long-standing resource [leak][]
affecting our Duktape-based JS runtime – a bug that's been around for as long as
we've been using Duktape as our default JS runtime.

Anyway, there's really no easy way to dig into all of the areas where things
have improved, so definitely check out the changelog below.

Enjoy!


### Changes in 12.9.0

- Stalker now also available on ARM32. 🎉
- Stalker JS integrations no longer clobber *errno* / *LastError*.
- *Stalker.follow()* now reliable on x86 and ARM64, including when the target
  thread is in a syscall on Windows.
- Stalker is finally reliable on WoW64. Thanks [@zuypt][]!
- All dependencies have been updated to the latest and greatest. Most exciting
  is V8 8.4, supporting the latest JavaScript language features.
- Long-standing Duktape memory leak finally discovered and fixed. Thanks to
  [@disazoz][] for the bug-report that lead to this breakthrough.
- *Socket.connect()* no longer leaks the file-descriptor (and associated memory)
  on error. (Fixed by the GLib dependency upgrade.) Thanks for reporting,
  [@1215clf][]!
- *Kernel.read\*()* no longer leaks in the V8 runtime.
- UNIX build system moved to Meson 0.54.
- Windows build system moved to VS2019.
- Node.js prebuilds provided for v14, in addition to v10 and v12.
- Electron prebuilds provided for v8 and v9.
- Fedora packages for F32.
- Ubuntu packages for Ubuntu 20.04.
- Python bindings no longer using any deprecated APIs.
- Support for leanback-only Android apps. Thanks [@5murfette][]!
- iOS jailed spawn() w/o closure supported on arm64e. Thanks [@mrmacete][]!
- iOS usbmux pairing record plist parsing now also handles binary plists,
  fixing a long-standing issue where Frida would reject a tethered iOS USB
  device. Thanks [@pachoo][]!
- *ObjC.choose()* also supported on arm64e. Thanks [@mrmacete][]!
- *ObjC.protocols* enumeration finally working properly, and not just the first
  time. Thanks for reporting, [@CodeColorist][]!
- Initial support for Android 11 Developer Preview. Thanks [@abdawoud][]!
- MUSL libc compatibility.
- Support for older versions of glibc, so our binaries can run on a wide variety
  of desktop Linux systems.
- Libc shim also covers *memalign()* and supports newer GNU toolchains.
- Exceptor's POSIX backend is now detecting Thumb correctly on ARM32, which
  would previously result in random crashes.
- Exceptor no longer clobbers “rflags” (x86_64) and “cpsr” (ARM64) on i/macOS,
  and provides write access to the native context.
- Four essential i/macOS 64-bit syscalls added to the libc shim: *read()*,
  *write()*, *mmap()*, *munmap()*. Thanks [@mrmacete][]!
- iOS binaries now signed with the “skip-library-validation” entitlement for
  convenience. Thanks [@elvanderb][]!
- The frida-core Vala API bindings are no longer missing the *frida.Error* type.
- Our scripts now allow messages to be *post()*ed to them while they are in the
  *LOADING* state. This is useful when a script needs to make a synchronous
  request during *load()*. Thanks [@Gbps][]!
- Gadget finally supports early instrumentation with the V8 runtime on 64-bit
  ELF targets, where constructor functions would previously be run in the wrong
  order. Thanks [@tacesrever][]!
- Support for ADB channels beyond just TCP in *Device.open_channel()*.
  Thanks [@aemmitt-ns][]!
- Many new instructions supported in the *ArmWriter* and *ThumbWriter* APIs.
- Massive improvements to our ARM32 relocator implementations.
- Linux module enumeration working when invoked through loader.
- Linux symbol resolution improvements.
- Better argument list handling in the V8 runtime, treating *undefined* the same
  as in the Duktape runtime. Thanks [@mrmacete][]!
- CModule Stalker API is back in working order.
- CModule runtime now exposes *Thread.{get,set}_system_error()*.
- CModule is now a stub on Linux/MIPS, instead of failing to compile due to
  TinyCC not yet supporting MIPS.
- Capstone configured to support ARMv8 A32 encodings.

### Changes in 12.9.1

- The Python bindings' setup.py does the right thing for Python 3.x on macOS.

### Changes in 12.9.2

- Fruity (iOS USB) backend no longer emits a warning on stdio.

### Changes in 12.9.3

- Android 11 Developer Preview 4 is now supported. Thanks for the assist,
  [@enovella_][]!
- Linux file monitoring is back in great shape.
- ArmRelocator properly relocates ADD instructions involving the PC register.
- ThumbRelocator properly handles IT blocks containing an unconditional branch.
  This means Interceptor is able to hook even more tricky cases. Thanks
  [@bet4it][]!
- Stalker ARM32 also supports clone syscalls in Thumb mode.
- Stalker ARM32 now suppresses events around exclusive ops like the ARM64
  backend.
- Stalker ARM32 trust threshold support.
- Improved error-handling in ObjC and Java bridges, to avoid crashing the
  process on unsupported OSes.

### Changes in 12.9.4

- *ObjC.available* no longer pretends that the Objective-C runtime is available
  when it indeed is not. The error-handling refactoring in 12.9.3 broke this,
  and the regression went unnoticed due to this being a blind spot in our test
  coverage.
- Electron v9 is out, so we now only provide prebuilds for v9.

### Changes in 12.9.5

- iOS early instrumentation – i.e. spawn() – supported on latest unc0ver.
- iOS crash reporter integration ported to iOS 13.5.
- *SystemFunction* now implements *call()* and *apply()* in the Duktape runtime,
  and not only in the V8 runtime.
- Java bridge finally handles strings with embedded nuls, fixing a long-standing
  issue that's been around for as long as the Java bridge has existed. Thanks
  [@tacesrever][]!

### Changes in 12.9.6

- No changes except for proper Windows binaries this time. The Windows CI worker
  did not actually build anything last time around, and released stale binaries.

### Changes in 12.9.7

- iOS early instrumentation more reliable on the unc0ver jailbreak: we now load
  *substrate-inserter.dylib* as part of our early instrumentation. This means
  it gets a chance to bootstrap the process, and lets you hook system APIs
  hooked by the bootstrapper without worrying about the bootstrapper getting
  confused when it encounters your hooks. Thanks [@mrmacete][]!


[Stalker]: /docs/stalker/
[what other functions does this function call]: https://codeshare.frida.re/@oleavr/who-does-it-call/
[Here]: https://github.com/frida/frida-presentations/blob/master/R2Con2017/02-transforms/06-return-values.js
[r2con presentation]: https://youtu.be/sBcLPLtqGYU
[CModule]: /docs/javascript-api/#cmodule
[optional chaining]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Optional_chaining
[nullish coalescing operator]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Nullish_coalescing_operator
[frida-compile]: https://github.com/oleavr/frida-agent-example
[leak]: https://github.com/svaarala/duktape/pull/2282
[@zuypt]: https://github.com/zuypt
[@disazoz]: https://github.com/disazoz
[@1215clf]: https://github.com/1215clf
[@5murfette]: https://github.com/5murfette
[@mrmacete]: https://twitter.com/bezjaje
[@pachoo]: https://github.com/pachoo
[@CodeColorist]: https://twitter.com/CodeColorist
[@abdawoud]: https://github.com/abdawoud
[@elvanderb]: https://twitter.com/elvanderb
[@Gbps]: https://github.com/Gbps
[@tacesrever]: https://github.com/tacesrever
[@aemmitt-ns]: https://github.com/aemmitt-ns
[@enovella_]: https://twitter.com/enovella_
[@bet4it]: https://github.com/bet4it
