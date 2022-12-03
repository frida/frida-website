---
layout: news_item
title: 'Frida 16.0.7 Released'
date: 2022-12-02 22:52:59 +0100
author: oleavr
version: 16.0.7
categories: [release]
---

It's been a busy week. Let's dive in.

## Sandboxed environments

This week [@hsorbo][] and me spent some days trying to get Frida working better
in sandboxed environments. Our goal was to be able to get Frida into Apple's
SpringBoard process on iOS. But to make things a little interesting, we figured
we'd start with *imagent*, the daemon that handles the iMessage protocol. It has
been hardened quite a bit in recent OS versions, and Frida was no longer able to
attach to it.

So we first started out with this daemon on macOS, just to make things easier to
debug. After finding the daemon's sandbox profile at
`/System/Library/Sandbox/Profiles/com.apple.imagent.sb`, it was hard to miss the
syscall policy. It disallows all syscalls by default, and carefully enables some
groups of syscalls, plus some specific ones that it also needs.

We then discovered that Frida's use of the pipe() syscall was the first hurdle.
This code is not actually in Frida itself, but in GLib, the excellent library
that Frida uses for data structures, cross-platform threading primitives, event
loop, etc. It uses pipe() to implement a primitive needed for its event loop.
More precisely, it uses this primitive to wake up the event loop's thread in
case it is blocking in a poll()-style syscall.

Anyway, we noticed that kqueue() is part of the groups of syscalls explicitly
allowed. Given that Apple's kqueue() supports polling file-descriptors and Mach
ports at the same time, among other things, it's likely to be needed in a lot of
places, and thus allowed by a broad range of sandbox profiles. It is also a
great fit for us, since EVFILT_USER means there is a way to wake up the event
loop's thread. Not just that, but it doesn't cost us a single file-descriptor.

After lots of coffee and fun pair-programming, we arrived at a [patch][] that
switches GLib's event loop over to kqueue() on OSes that support it. This got
us to the next hurdle: Frida is using socket APIs for file-descriptor passing,
part of the child-gating feature used for instrumenting children of the current
process. However, since hardened system services aren't likely to be allowed to
do things like fork() and execve(), it is fine to simply degrade this part of
our functionality. That was [tackled][] next, and boom… Frida is finally able
to attach to *imagent*. 🎉 Yay!

Next up we moved over to iOS and took it for a spin there. Much to our surprise,
Frida could attach to SpringBoard right out of the gate. Later we tried
*notifyd* and *profiled*, and could attach to those too. Even on latest iOS 16.
But, there's still work to do, as Frida cannot yet attach to *imagent* and
*WebContent* on iOS. This is exciting progress, though.

## Injection on iOS >= 15

While doing all of this we also tracked down a crash on iOS where frida-server
would get killed due to *EXC_GUARD* during injection on iOS >= 15. That has now
also been fixed, just in time for the release!

## DebugSymbol API

Another exciting piece of news is that [@mrmacete][] improved our DebugSymbol
API to consistently provide the full path instead of only the filename. This was
a long-standing inconsistency across our different platform backends. While at
it he also exposed the *column*, so you also get that in addition to the line
number.

## Interceptor.replace(), but fast

Last but not least it's worth mentioning an exciting new improvement in
Interceptor. For those of you using it from C, there's now *replace_fast()*
to complement *replace()*. This new fast variant emits an inline hook that
vectors directly to your replacement. You can still call the original if you
want to, but it has to be called through the function pointer that Interceptor
gives you as an optional out-parameter. It also cannot be combined with
*attach()* for the same target. It is a lot faster though, so definitely good to
be aware of when needing to hook functions in hot code-paths.

## EOF

That's all this time. Enjoy!

### Changelog

- darwin: Disable advanced features in hardened processes.
- darwin: Port GLib's MainContext to use kqueue() instead of poll().
- darwin: Fix EXC_GUARD during injection on iOS >= 15.
- package-server-ios: Port launchd plist to iOS 16.
- gadget: Do not cloak main thread while loading.
- debug-symbol: Ensure path is absolute and add column field. Thanks
  [@mrmacete][]!
- darwin: Add *query_hardened()*.
- interceptor: Add *replace_fast()*.
- interceptor: Reduce memory usage per target.


[@hsorbo]: https://twitter.com/hsorbo
[patch]: https://github.com/frida/glib/commit/99ec1f987dfbc9b0ab45ac32dd98464cc023cd42
[tackled]: https://github.com/frida/frida-core/commit/d31a5437c583eee49da9c710d10b8c3aa89710bb
[@mrmacete]: https://twitter.com/bezjaje
