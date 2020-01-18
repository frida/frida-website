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
