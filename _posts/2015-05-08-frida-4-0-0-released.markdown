---
layout: news_item
title: 'Frida 4.0.0 Released'
date: 2015-05-08 23:00:00 +0100
author: oleavr
version: 4.0.0
categories: [release]
---

It's time for an insane release with tons of improvements.

Let's start with a user-facing change. The CLI tool called *frida-repl* has
been renamed to just *frida*, and now does tab completion! This and some other
awesome REPL goodies were contributed by [@fitblip](https://github.com/fitblip).

There is also integrated support for launching scripts straight from the shell:

{% highlight sh %}
$ frida Calculator -l calc.js
    _____
   (_____)
    |   |    Frida 4.0.0 - A world-class dynamic
    |   |                  instrumentation framework
    |`-'|
    |   |    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'

# The code in calc.js has now been loaded and executed
[Local::ProcName::Calculator]->
# Reload it from file at any time
[Local::ProcName::Calculator]-> %reload
[Local::ProcName::Calculator]->
{% endhighlight %}

Or, perhaps you're tired of console.log() and would like to set some breakpoints
in your scripts to help you understand what's going on? Now you can, because
Frida just got an integrated Node.js-compatible debugger.

![Yo Dawg](https://cdn.meme.am/instances/500x/61299733.jpg "Yo Dawg")

Yep yep, but it is actually quite useful, and all of the CLI tools provide
the `--debug` switch to enable it:

{% highlight bash %}
# Connect Frida to a locally-running Calculator.app
# and load calc.js with the debugger enabled
$ frida Calculator -l calc.js --debug
    _____
   (_____)
    |   |    Frida 4.0.0 - A world-class dynamic
    |   |                  instrumentation framework
    |`-'|
    |   |    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'

Debugger listening on port 5858
# We can now run node-inspector and start debugging calc.js
[Local::ProcName::Calculator]->
{% endhighlight %}

Here's what it looks like:

![Frida Debugger Session](/img/frida-debug.png "Frida Debugger Session")

Ever found yourself wanting to *frida-trace* Objective-C APIs straight from
the shell? Thanks to [@Tyilo](https://github.com/Tyilo) you now can:

{% highlight bash %}
# Trace ObjC method calls in Safari
$ frida-trace -m '-[NSView drawRect:]' Safari
{% endhighlight %}

There are also other goodies, like brand new support for generating backtraces
and using debug symbols to symbolicate addresses:

{% highlight js %}
var f = Module.findExportByName("libcommonCrypto.dylib",
    "CCCryptorCreate");
Interceptor.attach(f, {
    onEnter: function (args) {
        console.log("CCCryptorCreate called from:\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n") + "\n");
    }
});
{% endhighlight %}

Or perhaps you're on Windows and trying to figure out who's accessing certain
memory regions? Yeah? Well check out the brand new
[MemoryAccessMonitor](/docs/javascript-api/#memoryaccessmonitor). Technically
this code isn't new, but it just hasn't been exposed to the JavaScript API
until now.

Another nice feature is that starting with this release it is no longer
necessary to forward multiple TCP ports when using `frida-server` running
on another device, e.g. Android.

There is now also much better error feedback propagated all the way from a
remote process to different exceptions in for example Python. With the previous
release attaching to an inexistent pid on Mac would give you:

{% highlight python %}
SystemError: GDBus.Error:org.gtk.GDBus.UnmappedGError.Quark._g_2↩
dio_2derror_2dquark.Code0: task_for_pid() for remote pid failed w↩
hile trying to make pipe endpoints: (os/kern) failure (5)
{% endhighlight %}

Whoah, madness. This is now simply:

{% highlight python %}
frida.ProcessNotFoundError: unable to find process with pid 1234
{% endhighlight %}

That's better. Let's talk about performance. Perhaps you used frida-trace and
wondered why it spent so much time “Resolving functions...”? On a typical iOS
app resolving just one function would typically take about 8 seconds.
This is now down to ~1 second. While there were some optimizations possible,
I quickly realized that no matter how fast we make the enumeration of function
exports, we would still need to transfer the data, and the transfer time alone
could be unreasonable. Solution? Just move the logic to the target process and
transfer the logic instead of the data. Simple.
Also, the Dalvik and ObjC interfaces have been optimized so seconds have been
reduced to milliseconds. The short story here is further laziness in when we
interrogate the language runtimes. We took this quite far in the ObjC interface,
where we now use ES6 proxies to provide a more idiomatic and efficient API.

That brings us to the next topic. The ObjC interface has changed a bit.
Essentially:

{% highlight js %}
var NSString = ObjC.use("NSString");
{% endhighlight %}

is now:

{% highlight js %}
var NSString = ObjC.classes.NSString;
{% endhighlight %}

You still use `ObjC.classes` for enumerating the currently loaded classes,
but this is now behaving like an object mapping class name to a JavaScript ObjC
binding.

Also, there's no more casting, so instead of:

{% highlight js %}
var NSSound = ObjC.use('NSSound');
var sound = ObjC.cast(ptr("0x1234"), NSSound);
{% endhighlight %}

You just go:

{% highlight js %}
var sound = new ObjC.Object(ptr("0x1234"));
{% endhighlight %}

Yep, no more class hierarchies trying to mimic the ObjC one. Just a fully
dynamic wrapper where method wrappers are built on the first access, and
the list of methods isn't fetched unless you try to enumerate the object's
properties.

Anyway, this is getting long, so let's summarize the other key changes:

- The Dalvik interface now handles varargs methods. Thanks to
  [@dmchell](https://github.com/dmchell) for reporting and helping track this
  down.
- *NativePointer* also provides `.and()`, `.or()` and `.xor()` thanks to
  [@Tyilo](https://github.com/Tyilo).
- The Interceptor's *onEnter*/*onLeave* callbacks used to expose the CPU
  registers through `this.registers`, which has been renamed to `this.context`,
  and now allows you to write to the registers as well.
- *Process.enumerateThreads()*'s thread objects got their CPU context field
  renamed from `registers` to `context` for consistency.
- Synchronous versions of enumerateFoo() API available as enumerateFoo**Sync**()
  methods that simply return an array with all of the items.
- `Memory.readCString()` is now available for reading ASCII C strings.
- `Frida.version` can be interrogated to check which version you're running,
  and this is also provided on the *frida-core* end, which for example is
  exposed by *frida-python* through `frida.__version__`.
- *Stalker* now supports the *jecxz* and *jrcxz* instructions. This is good news
  for [CryptoShark](https://github.com/frida/cryptoshark), which should soon
  provide some updated binaries to bundle the latest version of Frida.
- V8 has been updated to 4.3.62, and a lot of ES6 features have been enabled.
- We're now using a development version of the upcoming Capstone 4.0.
- All third-party dependencies have been updated to the latest and greatest.
- Windows XP is now supported. This is not a joke. I realized that we didn't
  actually use any post-XP APIs, and as I had to rebuild the dependencies on
  Windows I figured we might as well just lower our OS requirements to help
  those of you still instrumenting software on XP.

Enjoy!
