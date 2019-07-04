---
layout: news_item
title: 'Frida 12.6 Released'
date: 2019-05-28 02:00:00 +0200
author: oleavr
version: 12.6
categories: [release]
---

After a flurry of fixes across all platforms over the last few weeks,
I figured it was time to do another minor bump to call attention to
this release.

One particular fix is worth mentioning specifically. There was a long-
standing bug in our Android Java integration, where exception delivery
would intermittently result in the process crashing with
*GetOatQuickMethodHeader()* typically in the stack-trace. Shout-out to
[Jake Van Dyke][] and [Giovanni Rocca][] for helping track this one
down. This bug has been around for as long as ART has been supported,
so this fix is worth celebrating. 🎉

Our V8 runtime is also a lot more stable, child-gating works better
than ever before, Android device compatibility is much improved, etc.

So bottom line is that this is the most stable version of Frida ever
released – and now is the time to make sure you're running Frida 12.6.

Enjoy!

### Changes in 12.6.1

- The exception delivery fix in the Android Java integration introduced
  a performance bottleneck when running the VM in interpreter mode, e.g.
  through *Java.deoptimizeEverything()*. For example when running the
  Dropbox app from start to login screen, this would take ~94 seconds
  on a Pixel 3 running Android 9, and now takes ~6 seconds.

### Changes in 12.6.2

- Android Java integration now supports more arm64 systems thanks to a
  fix contributed by [Giovanni Rocca][].
- Android Java integration once again supports being used by more than
  one script at a time.

### Changes in 12.6.3

- *Java.choose()* is now working again on Android >= 8.1, thanks to a
  fix contributed by [Eugene Kolo][].
- Android Java integration unhooking is now working again. This also
  means hooks are properly reverted on script unload.
- Frida can now talk to old versions of Frida, from before the addition
  of per-script runtime selection.

### Changes in 12.6.4

- Build system is back in business on all platforms.

### Changes in 12.6.5

- Linux thread enumeration is now working properly on x86-64.
- Stalker finally handles restartable Linux syscalls.

### Changes in 12.6.6

- Android Java integration is back in fully working condition on 32-bit ARM.

### Changes in 12.6.7

- Latest Chimera iOS jailbreaks are now supported; confirmed working on *1.0.8*.
- Linux injector handles target processes where the libc's name is ambiguous,
  which is often an issue on Android.

### Changes in 12.6.8

- *ObjC.Object* now provides *$moduleName*, useful for determining which module
  owns a given class. Kudos to [David Weinstein][] for contributing this neat
  feature!

### Changes in 12.6.9

- Latest unc0ver jailbreak is now fully supported.
- Early instrumentation logic has been improved to fully support iOS 12. Kudos
  to [Francesco Tamagni][] for helping get these tricky changes across the
  finish-line.
- Enumeration of memory ranges is now more reliable on iOS 12, as memory ranges
  belonging to threads are now correctly cloaked.
- Cloaked memory ranges are now compacted, making lookups faster.
- Child gating is able to hold children for longer than 25 seconds. Previously
  these would get resumed automatically after that accidental timeout. This also
  affects early instrumentation on Android, as it is built on top of child
  gating.
- Swift bindings support RPC and have been moved to Swift 5.0, thanks to
  [John Coates][]' awesome contribution.


[Jake Van Dyke]: https://twitter.com/giantpune
[Giovanni Rocca]: https://twitter.com/iGio90
[Eugene Kolo]: https://twitter.com/eugenekolo
[David Weinstein]: https://twitter.com/insitusec
[Francesco Tamagni]: https://twitter.com/bezjaje
[John Coates]: https://twitter.com/JohnCoatesDev
