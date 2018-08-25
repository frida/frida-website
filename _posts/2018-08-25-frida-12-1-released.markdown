---
layout: news_item
title: 'Frida 12.1 Released'
date: 2018-08-25 23:00:00 +0200
author: oleavr
version: 12.1
categories: [release]
---

Massive changes under the hood this time. All of our dependencies have been
upgraded to the latest and greatest. Let's have a look at the highlights.

### V8

Frida's V8 was previously at 6.2.2, and has now been upgraded to 7.0.242.
The move to such a new version of V8 means that the V8 debugger API is gone,
and has been replaced with the new V8 Inspector API that the latest Node.js
also uses. What's pretty awesome about it is that it's natively supported by
Google Chrome's Inspector.

To start using it, just tell Frida to use V8, by calling *session.enable_jit()*,
and then *session.enable_debugger()*.

Or when using the CLI tools:

{% highlight sh %}
$ frida-trace --enable-jit --debug -f /bin/cat -i read
{% endhighlight %}

Then in Google Chrome, right-click and choose “Inspect”, and click on the green
Node.js icon in the upper left corner of the Inspector. That's it, you are now
debugging your Frida scripts. That means a nifty console with auto-completion,
pause/continue, stepping, breakpoints, profiling, and heap snapshots. What makes
it really convenient is that the server listens on your host machine, so you can
call *enable_debugger()* on a session representing a process on your
USB-tethered Android device, and it all works the same.

Here's what it looks like:

![Console](/img/inspector-console.png "Console")
![Profiler](/img/inspector-profiler.png "Profiler")
![Heap Snapshot](/img/inspector-snapshot.png "Heap Snapshot")

Note however that V8 is currently not included in our prebuilt iOS binaries,
but it should be possible to get it running again on iOS now that it's able to
run without RWX pages. We do however plan on bridging Duktape's binary debugger
protocol behind the scenes so debugging "just works" with Duktape also, though
probably with a slightly reduced feature-set.

### Process.id

It is often quite useful to know the PID of the process that your agent is
executing inside, especially in [preloaded mode][]. So instead of requiring you
to use *NativeFunction* to call e.g. *getpid()*, this is now a lot simpler as
you can use the brand new `Process.id` property.

### Anything else?

No other features, but some really nice bug-fixes. Thanks to [mrmacete][] we are
now able to attach to *com.apple.WebKit.\** processes on iOS 11.x. And thanks to
[viniciusmarangoni][] this release also packs a couple of goodies for frida-java,
fixing one Android 8.0 regression and adding the ability to properly instrument
*system_server*.

Enjoy!


[preloaded mode]: https://frida.re/docs/modes/#preloaded
[mrmacete]: https://github.com/mrmacete
[viniciusmarangoni]: https://github.com/viniciusmarangoni
