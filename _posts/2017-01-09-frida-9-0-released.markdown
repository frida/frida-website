---
layout: news_item
title: 'Frida 9.0 Released'
date: 2017-01-09 01:00:00 +0200
author: oleavr
version: 9.0
categories: [release]
---

Some big changes this time. We now use our [Duktape][]-based JavaScript runtime
by default on all platforms, iOS app launching no longer piggybacks on Cydia
Substrate, and we are bringing some massive performance improvements. That, and
some bugfixes.

Let's talk about Duktape first. Frida's first JS runtime was based on [V8][],
and I'm really happy about that choice. It is however quite obvious that there
are use-cases where it is a bad fit.

Some systems, e.g. iOS, don't allow RWX memory<sup id="ios-rwx-sup">[1](#ios-rwx)</sup>,
and V8 won't run without that. Another example is resource-constrained embedded
systems where there just isn't enough memory. And, as reported by users from
time to time, some processes decide to configure their threads to have tiny
stacks. V8 is however quite stack-hungry, so if you hook a function called by
any of those threads, it won't necessarily be able to enter V8, and your hooks
appear to be ignored<sup id="v8-stack-sup">[2](#v8-stack)</sup>.

Another aspect is that V8 is way more expensive than Duktape for the native ⇔
JS transitions, so if your Frida agent is all about API hooks, and your hooks
are really small, you might actually be better off with Duktape. Garbage
collection is also more predictable with Duktape, which is good for hooking
time-sensitive code.

That said, if your agent is heavy on JavaScript, V8 will be way faster. It also
comes with native ES6 support, although this isn't too big a deal since
non-trivial agents should be using [frida-compile][], which compiles your code
to ES5.

So the V8 runtime is not going away, and it will remain a first-class citizen.
The only thing that's changing is that we pick Duktape by default, so that you
are guaranteed to get the same runtime on all platforms, with a high probability
that it's going to work.

However, if your use-case is JS-heavy, all you have to do is call
*Session#enable_jit()* before the first script is created, and V8 will be used.
For our CLI tools you may pass *--enable-jit* to get the same effect.

That was Duktape. What's the story about app launching and Substrate, then?
Well, up until now our iOS app launching was piggybacking on Substrate. This was
a pragmatic solution in order to avoid going into interoperability scenarios
where Frida and Substrate would both hook *posix_spawn()* in launchd and
xpcproxy, and step on each other.

It was however on my long-term TODO to fix this, as it added a lot of complexity
in other areas. E.g. an out-of-band callback mechanism so our Substrate plugin
could talk back to us at load time, having to manage temporary files, etc.
In addition to that, it meant we were depending on a closed source third-party
component, even though it was a soft-dependency only needed for iOS app
launching. But still, it was the only part of Frida that indirectly required
permanent modifications to the running system, and we really want to avoid
that.

Let's have a look at how the new app launching works. Imagine that you ran
this on your host machine that's got a jailbroken iOS device connected to it
over USB:

{% highlight bash %}
$ frida-trace -U -f com.atebits.Tweetie2 -i open
{% endhighlight %}

We're telling it to launch Twitter's iOS app and trace functions named *open*.
As a side-note, if you're curious about the details, frida-trace is written in
Python and is less than 900 lines of [code][], so it might be a good way to
learn more about building your own tools on top of Frida. Or perhaps you'd
like to improve frida-trace? Even better!

The first part that it does is that it gets hold of the first USB device and
launches the Twitter app there. This boils down to:

{% highlight py %}
import frida

device = frida.get_usb_device()
pid = device.spawn(["com.atebits.Tweetie2"])
{% endhighlight %}

What now happens behind the scenes is this:

1. We inject our [launchd.js][] agent into launchd (if not done already).
2. Call the agent's RPC-exported [prepareForLaunch()][] giving it the identifier
  of the app we're about to launch.
3. Call [SBSLaunchApplicationWithIdentifierAndLaunchOptions()][] so SpringBoard
  launches the app.
4. Our launchd.js agent then intercept launchd's *__posix_spawn()* and adds
  [POSIX_SPAWN_START_SUSPENDED][], and [signals back][] the identifier and PID.
  This is the */usr/libexec/xpcproxy* helper that will perform an exec()-style
  transition to become the app.
5. We then inject our [xpcproxy.js][] agent into this so it can hook
  *__posix_spawn()* and add *POSIX_SPAWN_START_SUSPENDED* just like our launchd
  agent did. This one will however also have *POSIX_SPAWN_SETEXEC*, so that
  means it will replace itself with the app to be launched.
6. We *resume()* the xpcproxy process and [wait for the exec][] to happen and the
  process to be suspended.

At this point we let the *device.spawn()* return with the PID of the app that
was just launched. The app's process has been created, and the main thread is
suspended at dyld's entrypoint. frida-trace will then want to attach to it
so it can load its agent that hooks *open*. So it goes ahead and does something
similar to this:

{% highlight py %}
session = device.attach(pid)
script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, 'open'), {
  onEnter: function () {
    console.log('open()');
  }
});
""")
script.load()
{% endhighlight %}

Now that it has applied the instrumentation, it will ask Frida to resume
the process so the main thread can call *main()* and have some fun:

{% highlight py %}
device.resume(pid)
{% endhighlight %}

Note that I did skip over a few details here, as the *attach()* operation is
actually a bit more complicated due to how uninitialized the process is, but
you can read more about that [here].

Finally, let's talk about footprint and performance. First, let's examine how
much disk space is required when Frida is installed on an iOS device and is
in a fully operational state:

<iframe width="600" height="400" src="https://live.amcharts.com/RmODB/embed/" frameborder="0"></iframe>

That's the 64-bit version, which is only 1.87 MB xz-compressed. The 32-bit
version is obviously even smaller. Quite a few optimizations at play here:

- We used to write the frida-helper binary out to a temporary file and spawn it.
  The meat of the frida-helper program is now statically linked into
  frida-server, and its entitlements have been boosted along with it. This
  binary is only necessary when Frida is used as a plugin in an unknown process,
  i.e. where we cannot make any guarantees about entitlements and code-signing.
  In the frida-server case, however, it is able to guarantee that all such
  constraints are met.
- The library that we inject into processes to be instrumented,
  *frida-agent.dylib*, is no longer written out to a temporary file. We use
  our own out-of-process dynamic linker to map it from frida-server's memory
  and directly into the address space of the target process. These mappings
  are made copy-on-write, so that means it is as memory-efficient as the old
  *dlopen()* approach was.
- V8 was disabled for the iOS binaries as it's only really usable on old
  jailbreaks where the kernel is patched to allow RWX pages.
  (If V8 is important to your use-case, you can build it like this:
   `make server-ios FRIDA_DIET=no`)
- The iOS package has been split into two, “Frida” for 64-bit devices, and
  “Frida for 32-bit devices” for old devices.
- Getting rid of the Substrate dependency for iOS app launching also meant
  we got rid of FridaLoader.dylib. This is however a very minor improvement.

Alright, so that's disk footprint. How about memory usage?

<iframe width="600" height="400" src="https://live.amcharts.com/jJkYT/embed/" frameborder="0"></iframe>

Nice. How about performance? Let's have a look:

<iframe width="600" height="400" src="https://live.amcharts.com/5ZTI5/embed/" frameborder="0"></iframe>

Note that these measurements include the time spent communicating from the
macOS host to the iOS device over USB.

Enjoy!


<b id="ios-rwx">1</b> Except if the process has an entitlement, although that's
limited to just one region. [↩](#ios-rwx-sup)

<b id="v8-stack">2</b>: It is technically possible to work around this by
having a per-thread side-stack that we switch to before calling into V8. We
did actually have this partially implemented in the past. Might be something
we should revive in the longer term. [↩](#v8-stack-sup)

[Duktape]: http://duktape.org/
[V8]: https://developers.google.com/v8/
[frida-compile]: https://github.com/frida/frida-compile
[launchd.js]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/launchd.js
[prepareForLaunch()]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/launchd.js#L18-L21
[SBSLaunchApplicationWithIdentifierAndLaunchOptions()]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/frida-helper-backend-glue.m#L560-L563
[POSIX_SPAWN_START_SUSPENDED]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/launchd.js#L60
[signals back]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/launchd.js#L85
[xpcproxy.js]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/xpcproxy.js
[wait for the exec]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/darwin-host-session.vala#L476-L478
[code]: https://github.com/frida/frida-python/blob/9c876f457cdee4d3dab6c05c8ab8c4bd72ca42d1/src/frida/tracer.py
[here]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/frida-helper-backend-glue.m#L835-L861
