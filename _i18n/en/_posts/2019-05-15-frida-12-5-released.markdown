---
layout: news_item
title: 'Frida 12.5 Released'
date: 2019-05-15 23:00:00 +0200
author: oleavr
version: 12.5
categories: [release]
---

This is one packed release. So many things to talk about.

### V8

The main story this time is [V8][]. But first, a little background.

Frida uses the [Duktape][] JavaScript runtime by default to provide
scriptable access to its instrumentation core, [Gum][]. We were
originally only using V8, but as V8 used to depend on operating support
for *RWX* pages – i.e. executable pages of memory that are also
writable – we ended up adding a secondary JS runtime based on Duktape.
Due to this OS constraint with V8, and the fact that Duktape lacks
support for the latest JS syntax and features, I decided to make Duktape
our default runtime so that scripts written for one platform wouldn't
need any syntactic changes to work on another. Duktape was basically the
lowest common denominator.

Fast forward to today, and V8 no longer depends on OS support for *RWX*
pages. It's actually moving towards flipping between *RW-* and *R-X* by
default. By doing so it means it can be used on modern iOS jailbreaks,
and also on jailed iOS if the process is marked as being debugged,
so it is able to run unsigned code. But there's more; V8 can now even run
[JIT-less][], which means Frida can use V8 on every single platform, and
users no longer have to [frida-compile][] their agents to use the latest
JavaScript syntax and features. This last point only applies to trivial
agents, though, as being able to split a non-trivial agent into multiple
source files is still desirable. Plus, frida-compile makes it easy to
use [TypeScript][], which is highly recommended for any non-trivial
Frida agent.

So with all of that in mind, it was clearly time to upgrade our V8 to
the latest and greatest. As of this release we are running [7.6.48][],
and we also have a much deeper integration with V8 than ever before.
Both C++ memory allocations and page-level allocations are now managed
by Frida, so we are able to hide these memory ranges from APIs like
*Process.enumerateRanges()*, and also avoid poisoning the application's
own heap with allocations belonging to Frida. These details may not
sound all that significant, but are actually crucial for implementing
memory-dumping tools on top of Frida. Not only that, however, we also
interfere less with the process that is being observed. That means
there's a smaller risk of it exhibiting a different behavior than when
it runs without instrumentation.

### Runtime Selection

You may remember the *session.enable_jit()* API. It has finally been
deprecated, as you can now specify the desired runtime during script
creation. E.g. using our Python bindings:

{% highlight python %}
script = session.create_script(source, runtime='duk')
{% endhighlight %}

And using our Node.js bindings:

{% highlight js %}
const script = await session.createScript(source, {
  runtime: 'v8'
});
{% endhighlight %}

### Stalker

Another significant change in this release is that [Stalker][] no longer
depends on *RWX* pages on arm64, thanks to [John Coates][]' awesome
contribution. This means Stalker is finally much more accessible on iOS.

For those of you using Stalker on 64-bit Windows and stalking 32-bit
processes, it finally handles the WOW64 transitions on newer versions of
Windows. This brain-twisting improvement was contributed by [Florian Märkl][].

### Module.load()

There are times when you might want to load your own shared library,
perhaps containing hooks written in C/C++. On most platforms you could
achieve this by using [NativeFunction][] to call *dlopen()* (POSIX) or
*LoadLibrary()* (Windows). It's a very different story on newer versions
of Android, however, as their *dlopen()*-implementation looks at the
caller and makes decisions based on it. One such decision is whether
the app is trying to access a private system API, which would make it
hard for them to later remove or break that API. So as of Android 8
the implementation will return *NULL* when this is the case. This was
a challenge that Frida solved for its own injector's needs, but users
wanting to load their own library were basically on their own.

As of Frida 12.5, there's a brand new JavaScript API that takes care of
all the platform-specific quirks for you:

{% highlight js %}
const hooks = Module.load('/path/to/my-native-hooks.so');
Interceptor.replace(Module.getExportByName('libc.so', 'read'),
    hooks.getExportByName('replacement_read'));
{% endhighlight %}

### Android

We fixed so many Android-specific bugs in this release. For example,
*Module.getExportByName()* on an app-bundled library no longer results
in the library being loaded a second time at a different base address.
This bug alone is reason enough to make sure you've got all your devices
upgraded and running the latest release.

### iOS

The iOS Chimera jailbreak is also supported thanks to
[Francesco Tamagni][]'s awesome contributions.

### All the rest

There's also lots of other improvements across platforms.

In chronological order:

- Child gating also works on older versions of Windows.
  Thanks [Fernando Urbano][]!
- Executables are smaller on UNIX OSes as they no longer export any
  dynamic symbols.
- Frida's agent and gadget no longer crash on 32-bit Linux when loaded
  at a high address, i.e. where MSB is set.
- Only one of the two *frida-helper-{32,64}* binaries for Linux/Android
  is needed, and none of them for builds without cross-arch support.
  This means smaller footprint and improved performance.
- Linux/ARM64 is finally supported, with binaries uploaded as part of
  the release process.
- We now provide a hint about Magisk Hide when our early instrumentation
  fails to instrument Zygote on Android.

### Changes in 12.5.1

- Script runtime can be specified per script, deprecating *enable_jit()*.

### Changes in 12.5.2

- Gadget no longer crashes at script load time when using V8 on Linux
  and Android. Huge thanks to [Leon Jacobs][] for reporting and helping
  track this one down.

### Changes in 12.5.3

- Android linker integration supports a lot more devices.
- Android Java integration no longer crashes with “Invalid instruction”
  on some arm64 devices. Kudos to [Jake Van Dyke][] for reporting and
  helping track this one down.
- LineageOS 15.1 is supported after adding a missing SELinux rule.

### Changes in 12.5.4

- Hooks are no longer able to interfere with our V8 page allocator
  integration.
- Android stability improved greatly after plugging a hole in our libc
  shim. Big thanks to [Giovanni Rocca][] for reporting and helping track
  this one down!

### Changes in 12.5.5

- Apple USB devices are properly detected on Windows. Thanks [@xiofee][]!

### Changes in 12.5.6

- Android Java integration now has a workaround for a bug in ART's
  exception delivery logic, where one particular code-path assumes that
  there is at least one Java stack frame present on the current thread.
  That is however not the case on a pure native thread, like Frida's JS
  thread. Simplest reproducer is *Java.deoptimizeEverything()* followed
  by *Java.use()* of a non-existent class name. Kudos to
  [Jake Van Dyke][] for reporting and helping track this one down.
- Android Java integration no longer crashes the process when calling
  *Java.deoptimizeEverything()* in a process unable to TCP listen().
- Android Java integration supports JNI checked mode like it used to.
- Node.js 12 supported in addition to 8 and 10, with prebuilds for all
  supported platforms.
- Node.js bindings' *enableDebugger()* method no longer requires
  specifying which port to listen on.

### Changes in 12.5.7

- Android teardown no longer crashes on systems where we are unable to
  spawn *logcat* for crash reporting purposes.
- Better *SuperSU* integration teardown logic on Android.
- Android Java integration now properly supports JNI checked mode, which
  massively improves Android ROM compatibility. Kudos to [@muhzii][] for
  reporting and assisting with testing the changes.
- V8 backend teardown no longer suffers from a use-after-free, and also
  no longer crashes when a WeakRef is bound late.

### Changes in 12.5.8

- Linux child-gating now handles children changing architecture, e.g. a
  32-bit app doing fork+exec to run a 64-bit executable. Big thanks to
  [@gebing][] for the fix.
- Child gating no longer deadlocks in case of a fork+exec where a child
  process is not followed. Kudos to [@gebing][] for the fix.
- Module export lookups no longer fail on Android apps' own modules.

### Changes in 12.5.9

- Our libc shim now includes *memcpy()*, making it safe to hook. Thanks to
  [Giovanni Rocca][] for debugging and contributing the fix.
- *Interceptor.flush()* now also works even when a thread has temporarily
  released the JS lock, e.g. while calling a *NativeFunction*.
- Android Java integration no longer crashes intermittently during ART
  exception delivery, e.g. when hooking *ClassLoader.loadClass()*. Kudos
  to [Jake Van Dyke][] and [Giovanni Rocca][] for helping track this one
  down. This bug has been around for as long as ART has been supported,
  so this fix is worth celebrating. 🎉
- Android Java integration no longer crashes processes where the *JDWP*
  transport cannot be started.


[V8]: https://v8.dev/
[Duktape]: https://duktape.org/
[Gum]: https://github.com/frida/frida-gum
[JIT-less]: https://v8.dev/blog/jitless
[frida-compile]: https://github.com/oleavr/frida-agent-example
[TypeScript]: https://www.typescriptlang.org/
[7.6.48]: https://chromium.googlesource.com/v8/v8/+/refs/tags/7.6.48
[Stalker]: https://frida.re/docs/javascript-api/#stalker
[John Coates]: https://twitter.com/JohnCoatesDev
[Florian Märkl]: https://twitter.com/thestr4ng3r
[NativeFunction]: https://frida.re/docs/javascript-api/#nativefunction
[Francesco Tamagni]: https://twitter.com/bezjaje
[Fernando Urbano]: https://github.com/ineedblood
[Leon Jacobs]: https://twitter.com/leonjza
[Jake Van Dyke]: https://twitter.com/giantpune
[Giovanni Rocca]: https://twitter.com/iGio90
[@xiofee]: https://github.com/xiofee
[@muhzii]: https://github.com/muhzii
[@gebing]: https://github.com/gebing
