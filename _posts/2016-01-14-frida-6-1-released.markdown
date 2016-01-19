---
layout: news_item
title: 'Frida 6.1 Released'
date: 2016-01-14 19:00:00 +0100
author: oleavr
version: 6.1
categories: [release]
---

Some time ago [@s1341](https://github.com/s1341) ported Frida to QNX, and just a
few weeks back he was running into memory footprint issues when using Frida on
embedded ARM devices. This was right after he contributed pull-requests porting
Frida to linux-arm. We started realizing that it might be time for a new
JavaScript runtime, and agreed that [Duktape](http://duktape.org/) seemed like a
great fit for our needs.

This runtime has now landed, all tests are passing, and it even beats our V8
runtime on the measured overhead for a call to a hooked function with an empty
*onEnter*/*onLeave* callback. To give you an idea:

{% highlight sh %}
…/interceptor_on_enter_performance: V8 min=2 max=31 avg=2 OK
…/interceptor_on_enter_performance: DUK min=1 max=2 avg=1 OK
{% endhighlight %}

(Numbers are in microseconds, measured on a 4 GHz i7 running OS X 10.11.2.)

Anyway, even if that comparison isn't entirely fair, as we do some clever
recycling and copy-on-write tricks that we don't yet do in our V8 runtime, this
new runtime is already quite impressive. It also allows us to run on really tiny
devices, and the performance difference between a roaring JIT-powered monster
like V8 and a pure interpreter might not really matter for most users of Frida.

So starting with this release we are also including this brand new runtime
in all of our prebuilt binaries so you can try it out and tell us how it works
for you. It only adds a few hundred kilobytes of footprint, which is nothing
compared to the 6 MB that V8 adds per architecture slice. Please try it out
by passing `--disable-jit` to the CLI tools, or calling `session.disable_jit()`
before the first call to `session.create_script()`.

Considering that this new runtime also solves some issues that would require a
lot of work to fix in our JavaScriptCore runtime, like ignoring calls from
background threads and avoid poisoning the app's heap, we decided to get rid
of that runtime and switch to this new Duktape-based runtime on OSes where V8
cannot currently run, like on iOS 9. We feature-detect this at runtime, so you
still get to use V8 on iOS 8 like before – unless you explicitly `--disable-jit`
as just mentioned.

So in closing, here's a summary of the changes:

6.1.0:

- core: replace the JavaScriptCore runtime with its successor built on Duktape
- core: add *disable_jit()* to allow users to try out the new Duktape engine
- core: fix crash on Linux when injecting into processes where *pthread_create*
        has never been called/bound yet
- core: add support for linux-armhf (e.g. Raspberry Pi)
- python: add *disable_jit()* to Session
- node: add *disableJit()* to Session
- CLI tools: add *--disable-jit* switch
- frida-repl: upgrade to latest prompt-toolkit
- frida-trace: fix crash when attempting to trace partially resolved imports
- frida-trace: stick to ES5 in the generated handlers for Duktape compatibility

6.1.1:

- core: fix synchronization logic and error-handling bugs in the Duktape runtime

6.1.2:

- core: fix Android regression resulting in crash on inject
- core: fix Python 3.x build regression
- clr: add *DisableJit()* to Session

6.1.3:

- core: give the iOS frida-helper all the entitlements that the Preferences app
        has, so system session scripts can read and write system configuration
- core: changes to support AppContainer ACL on temporary directory/files within
- node: fix pid check so it allows attaching to the system session

Enjoy!
