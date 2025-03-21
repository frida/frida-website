---
layout: news_item
title: 'Frida 16.7.0 Released'
date: 2025-03-13 19:09:52 +0100
author: oleavr
version: 16.7.0
categories: [release]
---

One challenging aspect when instrumenting software is to deal with the dynamic
nature of things, from threads starting and terminating, to modules being loaded
and unloaded.

For example, if you're using Stalker to follow threads as they're executing,
this presents a couple of basic challenges, before even considering the
instrumentation itself.

## Which threads?

While you *can* use Interceptor to place an inline hook somewhere, so when a
thread does something interesting you then use Stalker to follow its execution,
there are times when you would rather call Process.enumerateThreads() and follow
the ones that you deem interesting.

Each thread may have a `name` you can use, but when it doesn't, you're typically
left with fuzzier options. You might look at its CPU registers provided by the
`context` property, or pass that to Thread.backtrace() to "fingerprint" it, or
perhaps you'd look at which threads spend the most CPU time during a certain
operation.

But what if you could figure out the thread's entrypoint routine and parameter?
Now you can:

{% highlight sh %}
$ frida -p 163431
Local::PID::163431 ]-> Process.enumerateThreads()
[
    …
    {
        "id": 163560,
        "name": "SDLAudioP1",
        "state": "waiting",
        "context": { … },
        "entrypoint": {
            "parameter": "0x561210844900",
            "routine": "0x7fc7781237c0"
        }
    }
]
{% endhighlight %}

## Future threads

Next there's the challenge of following threads that haven't started yet. Up
until now this required hooking OS-specific internals. And that's quite a lot of
complexity to maintain for cross-platform agents.

I'm excited to announce that we now provide an API for just this:

{% highlight js %}
const observer = Process.attachThreadObserver({
  onAdded(thread) {
    …
  },
  onRemoved(thread) {
    …
  },
  onRenamed(thread, previousName) {
    …
  }
});
{% endhighlight %}

The `onAdded` callback gets called with all existing threads right away, so the
initial state vs. updates can be managed easily without worrying about race
conditions. When called with a brand new thread, the call happens synchronously
from that new thread. So that's the perfect spot to Stalker.follow() it, so you
won't miss out on any instructions being executed early on.

Conversely, the `onRemoved` callback tells you when a thread is about to
terminate. The call happens synchronously from that thread, so you still have a
chance to execute some final code in the context of the thread.

And last but not least, the `onRenamed` callback tells you when a thread's
`name` just changed, along with its previous name, if it had one, or `null` if
not.

All of the callbacks are optional, but at least one must be provided.

Then, if you later want to stop observing, all you need to do is:

{% highlight js %}
observer.detach();
{% endhighlight %}

## Future modules

Just like threads come and go, so do modules/shared libraries. You might be
applying your instrumentation early, so you don't miss out on early activity.
But the earlier you apply your instrumentation, the more likely it is that other
parts of the application haven't been loaded yet.

While unloading may not actually happen, either because the application doesn't
do it, or because the dynamic loader doesn't support it, it's another aspect
that you might have to deal with.

Handling all of this has up until now required hooking OS-specific internals,
with all of the complexity it entails to maintain such code for cross-platform
agents.

I'm so excited to share that we now provide an API for this as well:

{% highlight js %}
const observer = Process.attachModuleObserver({
  onAdded(module) {
    …
  },
  onRemoved(module) {
    …
  }
});
{% endhighlight %}

Just like with Process.attachThreadObserver(), the `onAdded` callback gets
called with all existing modules right away, so the initial state vs. updates
can be managed easily without worrying about race conditions. When called with a
brand new module, the call happens synchronously right after that module has
been loaded, but before the application has had a chance to use it. This means
it's a good time to apply your instrumentation, using e.g. Interceptor.

Conversely, the `onRemoved` callback tells you when a module is gone.

Both of the callbacks are optional, but at least one must be provided.

Then, just like with the thread observer API, if you later want to stop
observing, all you need to do is:

{% highlight js %}
observer.detach();
{% endhighlight %}

## Profiling code

One little known feature in Gum, the C library at the heart of Frida, is its
library called gum-prof. It provides some lightweight building blocks for
profiling code. As of this release, we have finally exposed them to JavaScript.

Let's start with the main component, the Profiler API. It's a simple worst-case
profiler built on top of Interceptor:

{% highlight js %}
const profiler = new Profiler();
const sampler = new BusyCycleSampler();
for (const e of Process.getModuleByName('app-core.so')
      .enumerateExports()
      .filter(e => e.type === 'function')) {
  profiler.instrument(e.address, sampler);
}
{% endhighlight %}

Unlike a conventional profiler, which samples call stacks at a certain
frequency, you decide the exact functions that you're interested in profiling.
This is where things get interesting.

When any of those functions gets called, the profiler grabs a sample on entry,
and another one upon return. It then subtracts the two to compute how expensive
the call was. If the resulting value is greater than what it's seen previously
for the specific function, that value becomes its new worst-case.

Whenever a new worst-case has been discovered, it isn't necessarily enough to
know that most of the time/cycles/etc. was spent by a specific function. That
function may only be slow with certain input arguments, for example.

This is a situation where you can pass in a `describe()` callback for the
specific function when calling `instrument()`. Your callback should capture
relevant context from the argument list and/or other state, and return a string
that describes the new worst-case that was just discovered.

When you later decide to call `generateReport()`, you'll find your computed
descriptions embedded in each worst-case entry.

## Sampler

As you may have noticed in the Profiler example code that we just touched upon,
we now also have the notion of a "sampler". We actually have six different
implementations. What they all have in common is that they implement one method,
`sample()`, which returns a bigint representing the latest measurement. What it
denotes depends on the specific sampler, but to the Profiler this doesn't
matter, as it's only concerned with the amount of change between two points.

However, these samplers are also intended to be used directly for other
purposes.

These are the brand new samplers:

-   `CycleSampler`: measures CPU cycles, e.g. using the RDTSC instruction on x86
-   `BusyCycleSampler`: measures CPU cycles only spent by the current thread,
     e.g. using QueryThreadCycleTime() on Windows
-   `WallClockSampler`: measures passage of time
-   `UserTimeSampler`: measures time spent in user-space by a particular thread
-   `MallocCountSampler`: counts the number of calls to malloc(), calloc(), and
    realloc()
-   `CallCountSampler`: counts the number of calls to functions of your choosing

One cool example of how you might use `UserTimeSampler` is constructing it with
a thread ID, which means it will measure the time spent in user-space by that
particular thread. By constructing one such sampler per thread, and collecting
one sample from each, you can then exercise the application in some particular
way, like making sure it's fed a particular network packet. Then you'd collect
a second sample from each sampler, subtracting the previous sample to compute
the amount of change/delta. This tells you which thread spent the most time in
user-space, so you know which thread you might then want to Stalker.follow() to
study up close.

## EOF

There's also a slew of other exciting changes, so definitely check out the
changelog below.

Shot-out to [@hsorbo][] for the fun and productive pair-programming on random
parts of the thread and module observer features! 🙌 Kudos to [@mrmacete][]
and [@as0ler][] for helping test and shake out bugs 🥳

Enjoy!

## Changelog

- Introduce `Process.attachThreadObserver()` and `ThreadRegistry` for monitoring
  thread creation, termination, and renaming.
- Introduce `Process.attachModuleObserver()` and `ModuleRegistry` for monitoring
  module loading and unloading.
- gumjs: Expose Gum's Profiler and Sampler APIs to JavaScript.
- gumjs: Add `NativePointer#writeVolatile()` API. Thanks [@DoranekoSystems][]!
- fruity: Fix a crash in the Linux `getifaddrs()` logic where interfaces without
  an address weren't handled correctly.
- memory-access-monitor: Provide access to the thread ID and registers.
- darwin: Fix racy leakage of memory during teardown.
- linux: Avoid spurious .so ranges during injection.
- linux: Handle compat ranges during injection.
- server: Add --device for serving a specific device.
- compiler: Bump `@types/frida-gum` to 18.8.0.


[@DoranekoSystems]: https://github.com/DoranekoSystems
[@hsorbo]: https://twitter.com/hsorbo
[@mrmacete]: https://twitter.com/mrmacete
[@as0ler]: https://github.com/as0ler
