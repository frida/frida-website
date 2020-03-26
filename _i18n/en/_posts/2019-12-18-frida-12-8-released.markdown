---
layout: news_item
title: 'Frida 12.8 Released'
date: 2019-12-18 20:15:00 +0200
author: oleavr
version: 12.8
categories: [release]
---

Get ready for an exciting new release. This time around we're giving some long
overdue love to our [Stalker][] engine. It's been around for roughly ten years,
but it wasn't until Frida 10.5 in late 2017 that we [started][] unleashing its
massive potential.

Up until now we were able to Stalker.follow() existing threads and not only
observe them, but also mutate their instruction streams any way we'd like. It
could also be combined with Interceptor to instrument the current thread
between strategic points. This allowed us to build tools such as [AirSpy][].

But, what if we want to Stalker.follow() a NativeFunction call? This may seem
really simple, but reentrancy makes this really hard. It's easy to end up
following execution inside e.g. our private heap, and end up needing to allocate
memory for the instrumentation itself... all kinds of fun scenarios that are
mind-boggling to reason about.

The way we dealt with this was to teach Stalker to exclude certain memory
ranges, so that if it sees a call going to such a location it will simply emit
a call instruction there instead of following execution. So what we did was to
automatically exclude frida-agent's own memory range, and that way we didn't
have to deal with any of the reentrancy madness.

We also took care to special-case attempts to Stalker.follow() the current
thread, so that we queued that work until we're about to leave our runtime
and transition back into user code (or our main loop, in the case of the JS
thread).

That still left the big unanswered question of how to use Stalker in conjunction
with NativeFunction. We can now finally put that behind us:

{% highlight js %}
var open = new NativeFunction(
    Module.getExportByName(null, 'open'),
    'int', ['pointer', 'int'],
    { traps: 'all' }
);

Stalker.follow({
  events: {
    call: true
  },
  onReceive: function (e) {
    console.log(JSON.stringify(Stalker.parse(e)));
  }
});

var fd = open(Memory.allocUtf8String('/foo/bar'), 0);
console.log('open() =>', fd);
{% endhighlight %}

By setting the `traps: 'all'` option on the NativeFunction, it will re-activate
Stalker when called from a thread where Stalker is temporarily paused because
it's calling out to an excluded range – which is the case here because all of
frida-agent's code is marked as excluded.

We can also achieve the same goal for Objective-C methods:

{% highlight js %}
Stalker.follow({
  events: {
    call: true
  },
  onReceive: function (e) {
    console.log(JSON.stringify(Stalker.parse(e)));
  }
});

var NSAutoreleasePool = ObjC.classes.NSAutoreleasePool;
var NSFileManager = ObjC.classes.NSFileManager;

var fileExistsAtPath = NSFileManager['- fileExistsAtPath:']
    .clone({ traps: 'all' });

var pool = NSAutoreleasePool.alloc().init();
try {
  var manager = NSFileManager.defaultManager();
  var result = fileExistsAtPath.call(manager, '/foo/bar');
  console.log('fileExistsAtPath() =>', result);
} finally {
  pool.release();
}
{% endhighlight %}

And also for Java methods on Android:

{% highlight js %}
Stalker.follow({
  events: {
    call: true
  },
  onReceive: function (e) {
    console.log(JSON.stringify(Stalker.parse(e)));
  }
});

Java.perform(function () {
  var JFile = Java.use('java.io.File');
  var exists = JFile.exists.clone({ traps: 'all' });

  var file = JFile.$new('/foo/bar');
  var result = exists.call(file);
  console.log('exists() =>', result);
});
{% endhighlight %}

Yay. That said, these examples are barely scratching the surface of what's
possible using Stalker. One of the really cool use-cases is in-process fuzzing,
which [frida-fuzz][] is a great example of. There's also a bunch of other
use-cases, such as reversing, measuring code coverage, fault injection for
testing purposes, hooking inline syscalls, etc.

So that's the main story of this release. Would like to thank
[@andreafioraldi][] for the great bug-reports and help testing these tricky
changes.

### Wrapping up

One cool new feature worth mentioning is the new `ArrayBuffer.wrap()` API, which
allows you to conveniently and efficiently access memory regions as if they were
JavaScript arrays:

{% highlight js %}
var header = Memory.alloc(16);

var bytes = new Uint8Array(ArrayBuffer.wrap(header, 16));
bytes[0] = 1;
bytes[0] += 2;
bytes[1] = 2;

console.log(hexdump(header, { length: 16, ansi: true }));
console.log('First byte is:', bytes[0]);
{% endhighlight %}

This means you can hand over direct memory access to JavaScript APIs without
needing to copy memory in/out of the runtime. The only drawback is that bad
pointers won't result in a JS exception, and will crash the process.

We now also allow you to access the backing store of any ArrayBuffer, through
the new `unwrap()` method on ArrayBuffer. An example use-case for this is when
using an existing module such as [frida-fs][] where you get an ArrayBuffer that
you then want to pass to native code.

Kudos to [@DaveManouchehri][] for contributing the first draft of the
ArrayBuffer.wrap() API, and also big thanks to [@CodeColorist][] for suggesting
and helping shape the unwrap() feature.

### Changes in 12.8.0

- Stalker reactivation working properly.
- Stalker thread lifetime properly handled. Will also no longer crash when
  following a thread to its death on i/macOS.
- Safer garbage collection logic in Stalker.
- Making mistakes in the Stalker transform callback which ends up throwing a JS
  exception now results in Stalker.unfollow(), so the error doesn't get
  swallowed by the process crashing.
- Robust support for Stalker transform calling unfollow().
- Stalker support for older x86 CPUs without AVX2 support.
- Support for disabling automatic Stalker queue drain.
- NativeFunction is better at handling exceptions through the brand new
  Interceptor unwinding API.
- Java and ObjC APIs to specify NativeFunction options for methods through
  clone(options), and blocks through the second argument to ObjC.Block().
- ObjC class and protocol caching logic finally works. Thanks [@gebing][]!
- The prebuilt Python 3 extension for Windows finally supports all Python 3
  versions >= 3.4 on Windows, just like on the other platforms.
- ArrayBuffer wrap() and unwrap().
- DebugSymbol API has better error-handling on Linux/Android.
- Java integration no longer crashes in recompileExceptionClearForArm64() in
  system processes on Android 10.
- GumJS devkit on i/macOS supports V8 once again.

### Changes in 12.8.1

- The CModule Stalker integration is back in business.

### Changes in 12.8.2

- Thumb IT blocks are finally relocated correctly. This means we are able to
  hook a lot more functions on 32-bit ARM targets, e.g. Android. Thanks
  [@bigboysun][]!

### Changes in 12.8.3

- Java.ClassFactory.get() introduced to be able to work with multiple class
  loaders without worrying about colliding class names. This means that
  assigning to the *loader* property is now considered deprecated. We still
  keep it around for backwards compatibility, but using it alongside the new
  API is not supported.
- Java.enumerateLoadedClasses() also provides class handles and not just names.
- The JNI GetByteArrayRegion() function is now part of the Env wrapper. Thanks
  [@iddoeldor][]!

### Changes in 12.8.4

- Internal hooks no longer result in crashes on Linux/ELF targets when PLT/GOT
  entries haven't been warmed up.

### Changes in 12.8.5

- Python bindings finally provide properly encoded error messages on Python 2.x.

### Changes in 12.8.6

- Android linker detection is finally working again in sandboxed processes.
  This was a regression introduced in 12.7.8. Kudos to [@DaveManouchehri][]
  for reporting and helping track this one down!

### Changes in 12.8.7

- Our Node.js *IOStream* bindings received two critical stability improvements.
  Turns out the cancellation logic had a race-condition that resulted in the
  cancellable not always being used. There was also a bug in the teardown logic
  that could result in a stream being closed before all I/O operations had
  completed. Kudos to [@mrmacete][] for these awesome fixes!

### Changes in 12.8.8

- Gadget no longer deadlocks on Android/Linux during early instrumentation
  use-cases where Gadget's entrypoint gets called with dynamic linker lock(s)
  held. Due to Exceptor now using *dlsym()* to avoid running into PLT/GOT issues
  during early instrumentation, we need to ensure that Exceptor gets initialized
  from the entrypoint thread, and not the Gadget thread.

### Changes in 12.8.9

- Stalker's JavaScript integration is no longer performing a use-after-free in
  *EventSink::stop()*, i.e. after *Stalker.unfollow()*.

### Changes in 12.8.10

- Gadget is once again able to run on iOS without a debugger present. This was a
  regression introduced in 12.8.8. Kudos to [@ddzobov][] for reporting!

### Changes in 12.8.11

- The i/macOS Exceptor's API hooks no longer perform an OOB write when a
  user of the Mach exception handling APIs only requests a subset of the
  handlers. Such a user would typically be a crash reporter or analytics
  framework.
- Electron prebuilds are now provided for v8 (stable) and v9 (beta). We no
  longer provide prebuilds for v7.

### Changes in 12.8.12

- Massively overhauled Android Java integration, now using Proxy objects and
  CModule to lazily resolve things. And no more *eval*-usage to dynamically
  generate method and field wrappers – i.e. less memory required per wrapper
  generated. All of these changes reduce memory usage and allow *Java.use()*
  to complete much faster.
- Android Java integration provides uncensored access to methods and fields on
  Android versions that attempt to hide private APIs, i.e. Android >= 9.
- Way faster Android device enumeration. No longer running any *adb shell*
  commands to determine the device name when the locally running ADB daemon is
  new enough (i.e. ADB >= sometime during 2017).
- We've finally eliminated a long-standing memory leak on Linux-based OSes,
  affecting restricted processes such as *zygote* and *system_server* on newer
  versions of Android. This was a bug in our logic that garbage-collects
  thread-local data shortly after a given thread has exited. The mechanism that
  determines that the thread has indeed finished exiting would fail and never
  consider the thread gone. This would result in more and more garbage
  accumulating, with a longer and longer collection of garbage to iterate over.
  So not only would we be spending increasingly more time on futile GC attempts,
  we would also be eating CPU retrying a GC every 50 ms.
- The Python bindings allow obtaining a file-descriptor from a Cancellable in
  order to integrate it into event loops and other *poll()*-style use-cases.
  Worth noting that frida-tools 7.0.1 is out with a major improvement built on
  this: The CLI tools no longer delay for up to 500 ms before exiting. So
  short-lived programs like *frida-ls-devices* and *frida-ps* now feel very
  snappy.
- Duktape source-map handling now also works with scripts loaded by the REPL –
  where the inline source-map isn't the last line of the script due to the REPL
  appending its own code. This means stack-traces always contain meaningful
  filenames and line numbers.
- Duktape: the baked in JavaScript runtime – i.e. GumJS' glue code, ObjC, and
  Java – is now Babelified with the *loose* option enabled, to reduce bloat and
  improve performance. No modern JavaScript data structures leak out through the
  APIs, so there's no need to have Babel be spec-compliant.
- V8: the baked in JavaScript runtime is compressed, for a smaller footprint and
  faster code. This was previously only done to the Duktape one.
- Better Linux process name heuristics in *enumerate_processes()*.

### Changes in 12.8.13

- *Java.performNow()* is back in working order.
- Python bindings' setup.py now looks for a local *.egg* before attempting to
  download one, and expects the download to complete within two minutes.
  Kudos to [@XieEDeHeiShou][] for these nice improvements!

### Changes in 12.8.14

- The iOS Simulator is now properly supported, both in Gadget form and attaching
  to a running Simulator process from macOS. Kudos to [@insitusec][] for helping
  fix these issues!
- Gadget now also looks for its .config in the directory above on iOS, but only
  if its parent directory is named “Frameworks”. Kudos to [@insitusec][] for
  the suggestion!

### Changes in 12.8.15

- Brand new feature-complete support for iOS/arm64e, including new
  *NativePointer* methods: *sign()*, *strip()*, *blend()*.
- Latest iOS Unc0ver jailbreak is now supported. Kudos to [@mrmacete][] for
  the pull-request, and [@Pwn20wnd][] for the assistance! ❤️
- Improved support for the Chimera jailbreak, making sure its
  *pspawn_payload-stg2.dylib* is initialized. Thanks [@mrmacete][]!
- The i/macOS injector no longer fails when an agent entrypoint returns
  instantly.
- Better error message about needing Gadget for jailed iOS.
- Improved error-handling in the Windows injector to avoid crashing the target
  process when our DLL injection fails. Kudos [@dasraf9][]!
- Support for injection into live newborn targets on i/macOS, and also no longer
  treating suspended processes as needing to be prepared for injection,
  regardless of whether they actually need it.
- Improved iOS fault tolerance, handling frontmost iOS app name query failing.
- Improved Android fault tolerance, handling *zygote* and *system_server*
  processes dying without having to restart *frida-server*.
- Now able to launch *frida-server* during boot on Android 10, as
  *LD_LIBRARY_PATH* no longer interferes with the spawning of *frida-helper-32*.
  Kudos to [@enovella][] for helping track this one down!
- No more infinite loop when failing to handle *SIGABRT* on UNIXy platforms.
- We now support nested signals in Exceptor's POSIX backend. Kudos [@bannsec][]!
- Proper handling of invalid Windows ANSI strings. Thanks, [@clouds56][]!
- *Java.perform()* working properly again on Android < 5.
- Improved varargs-handling in *NativeFunction*, now promoting varargs smaller
  than int. Thanks for reporting, [@0x410c][]!

### Changes in 12.8.16

- Large CModule instances now working on iOS systems with 16K pages. Kudos to
  [@mrmacete][] for discovering and fixing this long-standing issue!
- Stalker also works in arm64 processes on iOS/arm64e. Kudos to [@AeonLucid][]
  for reporting and helping track this one down!

### Changes in 12.8.17

- Support for injection into live newborn targets on i/macOS turned out to cause
  regressions, so we've reverted it for now. Specifically, *notifyd* on iOS 12.4
  is a case where *libSystemInitialized* is not getting set. Need to dig deeper
  to figure out why, so decided to walk back this logic for now.

### Changes in 12.8.18

- New and improved *Java.scheduleOnMainThread()* to allow calling APIs such as
  *getApplicationContext()*. Kudos to [@giantpune][] for reporting!
- Ability to hook CriticalNative methods on newer versions of Android. Kudos to
  [@abdawoud][] for reporting!


[Stalker]: /docs/javascript-api/#stalker
[started]: /news/2017/08/25/frida-10-5-released/
[AirSpy]: https://github.com/nowsecure/airspy
[frida-fuzz]: https://twitter.com/andreafioraldi/status/1205194910372110337
[@andreafioraldi]: https://twitter.com/andreafioraldi
[frida-fs]: https://github.com/nowsecure/frida-fs
[@DaveManouchehri]: https://twitter.com/DaveManouchehri
[@CodeColorist]: https://twitter.com/CodeColorist
[@gebing]: https://github.com/gebing
[@bigboysun]: https://github.com/bigboysun
[@iddoeldor]: https://github.com/iddoeldor
[@mrmacete]: https://twitter.com/bezjaje
[@ddzobov]: https://github.com/ddzobov
[@XieEDeHeiShou]: https://github.com/XieEDeHeiShou
[@insitusec]: https://twitter.com/insitusec
[@Pwn20wnd]: https://twitter.com/Pwn20wnd
[@dasraf9]: https://github.com/dasraf9
[@enovella]: https://twitter.com/enovella_
[@bannsec]: https://twitter.com/bannsec
[@clouds56]: https://github.com/clouds56
[@0x410c]: https://github.com/0x410c
[@AeonLucid]: https://twitter.com/AeonLucid
[@giantpune]: https://twitter.com/giantpune
[@abdawoud]: https://github.com/abdawoud
