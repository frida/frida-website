---
layout: news_item
title: 'Frida 12.0 Released'
date: 2018-07-12 12:00:00 +0200
author: oleavr
version: 12.0
categories: [release]
---

As some of you may have picked up on, there may be a [book][] on Frida in the
works. In my day to day at [NowSecure][] I spend a good chunk of time as a user
of Frida's APIs, and consequently I'm often reminded of past design decisions
that I've since come to regret. Even though I did address most of them over the
years, some were so painful to address that I kept them on the backburner. Fast
forward to today, and the thought of publishing a book with all these in mind
got me thinking that it was time to bite the bullet.

This is why I'm stoked to announce Frida 12. We have finally reached a point
in Frida's evolution where our foundations can be considered sufficiently stable
for a book to be written.

Let's have a look at the changes.

### CLI tools

One thing that caused a bit of confusion in the past was the fact that our
Python bindings also came with some CLI tools. Frida is a toolkit for building
tools, and even though we provide a few sample tools it should be up to you if
you want to have them installed.

Up until now this meant anyone building a tool using our Python bindings would
end up depending on *colorama*, *prompt-toolkit*, and *pygments*, because our
CLI tools happen to depend on those.

Well, that changes now. If you do:

{% highlight sh %}
$ pip install frida
{% endhighlight %}

You will now only get our Python bindings. Nothing more. And this package has
zero dependencies.

The CLI tools might still be useful to you, though, so to install those do:

{% highlight sh %}
$ pip install frida-tools
{% endhighlight %}

### Convenience APIs in bindings

Something that seemed like a great idea at the time was having our language
bindings provide some convenience APIs on the [Session][] object. The thinking
was that simple use-cases that only need to enumerate loaded modules and perhaps
a few memory ranges, to then read or write memory, wouldn't have to load their
own agent. So both our Python and our Node.js bindings did this behind the
scenes for you.

Back then it was somewhat tedious to communicate with an agent as the [rpc][]
API didn't exist, but even so, it was a bad design decision. The [JS APIs][]
are numerous and not all can be exposed without introducing new layers of
complexity. Another aspect is that every language binding would have to
duplicate such convenience APIs, or we would have to add core APIs that
bindings could expose. Both are terrible options, and cause confusion by
blurring the lines, ultimately confusing people new to Frida. Granted, it did
make things easier for some very simple use-cases, like memory dumping tools,
but for everybody else it just added bloat and confusion.

These APIs are now finally gone from our Python and Node.js bindings. The other
bindings are unaffected as they didn't implement any such convenience APIs.

### Node.js bindings

It's been a few years since our Node.js bindings were written, and since then
Node.js has evolved a lot. It now supports ES6 classes, *async* / *await*, arrow
functions, *Proxy* objects, etc.

Just the *Proxy* support alone means we can simplify [rpc][] use-cases like:

{% highlight js %}
const api = await script.getExports();
const result = await api.add(2, 5);
{% endhighlight %}

to just:

{% highlight js %}
const result = await script.exports.add(2, 5);
{% endhighlight %}

Some of you may also prefer writing your application in [TypeScript][], which
is an awesome productivity boost compared to old-fashioned JavaScript. Not only
do you get type checking, but if you're using an editor like [VS Code][] you
also get type-aware refactoring and amazing code completion.

However, for type checking and editor features to really shine, it is crucial to
have type definitions for your project's dependencies. This is rarely ever an
issue these days, except for those of you using Frida's Node.js bindings.
Up until now we didn't provide any type definitions. This has finally been
resolved. Rather than augmenting our bindings with type definitions, I decided
to rewrite them in TypeScript instead. This means we also take advantage of
modern language features like ES6 classes and *async* / *await*.

We could have stopped there, but those of you using our Node.js bindings from
TypeScript would still find this a bit frustrating:

{% highlight js %}
script.events.listen('message', (message, data) => {
});
{% endhighlight %}

Here, the compiler knows nothing about which events exist on the *Script*
object, and what the callback's signature is supposed to be for this particular
event. We've finally fixed this. The API now looks like this:

{% highlight js %}
script.message.connect((message, data) => {
});
{% endhighlight %}

Voilà. Your editor can even tell you which events are supported and give you
proper type checking for the code in your callback. Sweet!

### Interceptor

Something that's caused some confusion in the past is the observation that
accessing *this.context.pc* from *onEnter* or *onLeave* would give you the
return address, and not the address of the instruction that you put the hook
on. This has finally been fixed. Also, *this.context.sp* now points at the
return address on x86, instead of the first argument. The same goes for
*Stalker* when using call probes.

As part of this refactoring breaking our backtracer implementations, I also
improved our default backtracer on Windows.

### Tether?

You might have wondered why:

{% highlight py %}
device = frida.get_usb_device()
{% endhighlight %}

Would give you a *Device* whose *type* was *'tether'*. It is now finally *'usb'*
as you'd expect. So our language bindings are finally consistent with our core
API.

### Changes in 12.0.1

- core: fix argument access on 32-bit x86
- core: update *Stalker* to the new *CpuContext* semantics
- python: publish the correct README to PyPI
- python: fix the Windows build system

### Changes in 12.0.2

- core: upgrade to Capstone's *next* branch
- core: fix the DbgHelp backtracer on Windows and update to latest DbgHelp
- python: fix long description
- java: fix hooking of *java.lang.Class.getMethod()*

### Changes in 12.0.3

- core: fix the iOS build system broken by Capstone upgrade

Enjoy!


[NowSecure]: https://www.nowsecure.com/
[book]: https://twitter.com/fridadotre/status/950085837445836800
[Session]: https://gist.github.com/oleavr/e6af8791adbef8fbde06#file-frida-core-1-0-vapi-L201-L226
[rpc]: https://frida.re/docs/javascript-api/#rpc
[JS APIs]: https://frida.re/docs/javascript-api/
[TypeScript]: https://www.typescriptlang.org/
[VS Code]: https://code.visualstudio.com/
