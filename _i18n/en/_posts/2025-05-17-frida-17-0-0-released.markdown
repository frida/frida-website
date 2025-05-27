---
layout: news_item
title: 'Frida 17.0.0 Released'
date: 2025-05-17 19:45:49 +0200
author: oleavr
version: 17.0.0
categories: [release]
---

After countless cups of coffee and fun coding sessions, [@hsorbo][] and I are
excited to bring you Frida 17.0.0. After nearly three years since the last major
bump, and struggling to find the right time to make breaking changes, we decided
it is finally time to do so.

## Runtime Bridges

The main thing that's been bothering us for quite some time was the fact that
our runtime bridges, i.e. frida-{objc,swift,java}-bridge, were bundled with
Frida's GumJS runtime. This came with some major pain points:

- Inertia: Being tied to Frida's release cycle.
- Bloat: For users who don't need a particular runtime bridge.
- Scalability: We'd like to see bridges for all kinds of runtimes, but the more
  we add to Frida the more we'll struggle with inertia and bloat.
- Discoverability: Community-maintained bridges being harder to discover, as
  they require a different workflow for consumption.

I've been hesitant to stop bundling them though, as requiring a build step for
custom agents seemed like it would add too much friction. And the thought of
breaking examples in books, blog posts, [CodeShare][] etc. didn't sit well with
me either.

The friction aspect is why we introduced the frida.Compiler API back in
[15.2][], along with frida-tools shipping a CLI tool, frida-compile, built on
top of it. Our REPL was also improved to support loading .ts (TypeScript)
directly, making use of frida.Compiler behind the scenes.

That's still an extra step though, which is too much for one-off scripts and
early prototyping work using the Frida REPL or frida-trace. And, it would
break a lot of examples. To remedy this, the just-released frida-tools 14.0.0
bakes the three bridges into its REPL and frida-trace agents.

Our bridges have also been migrated to ESM, so they can be consumed by the
latest versions of frida-compile. (Shout-out to [@yotamN][] for migrating
frida-java-bridge ♥️)

Those of you building Frida from source may also notice an improvement in build
times. Since we're no longer bundling the bridges, we could finally get rid of
Gum's frida-compile dependency, and stop depending on Node.js + npm for Gum
itself.

We still had GumJS' own runtime, which implements built-ins such as
`console.log()`, but porting it to ESM and simply baking in each module
individually meant we no longer needed a JavaScript bundler. This means faster
build times for Gum itself: on a Linux-powered i9-12900K system, builds dropped
from ~24s → ~6s.

You can see a quick reference tutorial inside [bridges][].

## Legacy-style enumeration APIs

Back in the day, our synchronous enumeration APIs all looked like this:

{% highlight javascript %}
Process.enumerateModules({
  onMatch(module) {
    console.log(module.name);
  },
  onComplete() {
  }
});
{% endhighlight %}

There was also an equivalent **Sync**-suffixed method, like
`Process.enumerateModulesSync()` for this particular example. The idea was that
the underlying implementation could become asynchronous, but for the time being
most of them weren't, so the Sync-suffixed implementation was just a thin
wrapper around the asynchronous-looking API.

Later, as more and more platforms were supported, I realized that all of the
pretend asynchronous implementations turned out to always be quick and cheap
operations. So offering an asynchronous flavor was going to be pointless. And
for the few that were truly asynchronous from the beginning, like
`Memory.scan()`, it still made sense to have them stay that way.

I was hesitant to break the API though, so I opted to add a check to each
unsuffixed implementation, so it would behave like its Sync-suffixed counterpart
if the callbacks argument was omitted. Wanting to migrate users off the
old-style API, I made sure to update our TypeScript bindings so only the modern
flavors were included.

The equivalent in modern style would then look like this:

{% highlight javascript %}
for (const module of Process.enumerateModules()) {
  console.log(module.name);
}
{% endhighlight %}

Where `Process.enumerateModules()` returns an array of Module objects.

These legacy-style APIs are now finally gone. Those of you writing your agents
in TypeScript won't need to do anything, unless you're using ancient versions of
our typings.

## Memory read/write APIs

Back in the day, you'd access memory like this:

{% highlight javascript %}
const playerHealthLocation = ptr('0x1234');
const playerHealth = Memory.readU32(playerHealthLocation);
Memory.writeU32(playerHealthLocation, 100);
{% endhighlight %}

The modern equivalent is:

{% highlight javascript %}
const playerHealthLocation = ptr('0x1234');
const playerHealth = playerHealthLocation.readU32();
playerHealthLocation.writeU32(100);
{% endhighlight %}

Where each write-counterpart returns the NativePointer itself, to support
chaining:

{% highlight javascript %}
const playerData = ptr('0x1234');
playerData
    .add(4).writeU32(13)
    .add(4).writeU16(37)
    .add(2).writeU16(42)
    ;
{% endhighlight %}

The legacy versions of these are now also gone, and have been gone from our
TypeScript bindings for as long as the legacy-style enumeration APIs. So this
change should also not be noticable to most of you.

## Static Module APIs

Now for the breaking changes that also affect users who were current with the
TypeScript bindings, prior to 19.0.0, released together with Frida 17. The
following static Module methods are now gone:

- Module.ensureInitialized()
- Module.findBaseAddress()
- Module.getBaseAddress()
- Module.findExportByName()
- Module.getExportByName()
- Module.findSymbolByName()
- Module.getSymbolByName()

These are all straight-forward to migrate away from.

But first, let's cover the odd one out:

{% highlight javascript %}
Module.getSymbolByName(null, 'open')
{% endhighlight %}

This is now accomplished like this:

{% highlight javascript %}
Module.getGlobalExportByName('open')
{% endhighlight %}

For the rest, you first need to look up the Module, and then access the desired
property or method on it. For example, instead of:

{% highlight javascript %}
Module.getExportByName('libc.so', 'open')
{% endhighlight %}

The new way is:

{% highlight javascript %}
Process.getModuleByName('libc.so').getExportByName('open')
{% endhighlight %}

The equivalent for Module.getBaseAddress() is thus:

{% highlight javascript %}
Process.getModuleByName('libc.so').base
{% endhighlight %}

This means there is now only one way to do Module introspection, and the API
design is such that we encourage you to write performant code. For example, in
the past you might have been tempted to do:

{% highlight javascript %}
const openImpl = Process.getExportByName('libc.so', 'open');
const readImpl = Process.getExportByName('libc.so', 'read');
{% endhighlight %}

But now you'll probably think twice before doing:

{% highlight javascript %}
const openImpl = Process.getModuleByName('libc.so').getExportByName('open');
const readImpl = Process.getModuleByName('libc.so').getExportByName('read');
{% endhighlight %}

And instead do:

{% highlight javascript %}
const libc = Process.getModuleByName('libc.so');
const openImpl = libc.getExportByName('open');
const readImpl = libc.getExportByName('read');
{% endhighlight %}

Which is both more readable and more performant.

Last but not least, the static enumeration APIs, such as
`Module.enumerateExports()`, are now also gone. These were however removed from
the TypeScript bindings way back, so most of you shouldn't need to deal with
these. But if you do, the migration looks exactly the same as above.

## EOF

So that's about it. Happy hacking!


[@hsorbo]: https://twitter.com/hsorbo
[CodeShare]: https://codeshare.frida.re/
[15.2]: /news/2022/07/21/frida-15-2-0-released/
[@yotamN]: https://github.com/yotamN
[bridges]: /docs/bridges
