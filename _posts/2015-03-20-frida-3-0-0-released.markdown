---
layout: news_item
title: 'Frida 3.0.0 Released'
date: 2015-03-20 23:00:00 +0100
author: oleavr
version: 3.0.0
categories: [release]
---

You may have wondered:

> Why a Python API, but JavaScript debugging logic?

That, my friend, is a question to be asked no more:

{% highlight sh %}
$ npm install frida
{% endhighlight %}

We just brought you brand new [Node.js bindings](https://github.com/frida/frida-node),
and they are fully asynchronous:

{% gist 6ecae99945ccba47427a %}

Check out the [examples](https://github.com/frida/frida-node/blob/46a5f92203ab86978a2af68d6c926d6d2b63fbe7/examples/interactive.js)
to get an idea what the API looks like. It's pretty much a 1:1 mapping of the
API provided by the Python bindings, but following Node.js / JavaScript
conventions like camelCased method-names, methods returning ES6 *Promise*
objects instead of blocking, etc.

Now, combine this with [NW.js](https://github.com/nwjs/nw.js/) and you can build
your own desktop apps with HTML, CSS, and JavaScript all the way through.

So, brand new Node.js bindings; awesome! We did not stop there, however.
But first, a few words about the future. I am excited to announce that I have
just started a company with the goal of sponsoring part-time development of
Frida. By offering reverse-engineering and software development expertise,
the goal is to generate enough revenue to pay my bills and leave some time
to work on Frida. Longer term I'm hoping there will also be demand for help
adding features or integrating Frida into third-party products.
In the meantime, however, if you know someone looking for reverse-engineering
or software development expertise, I would really appreciate it if you could
kindly refer them to get in touch. Please see [my CV](https://github.com/oleavr/cv/raw/master/oleavr.pdf)
for details.

That aside, let's get back to the release. Next up: 32-bit Linux support!
Even *Stalker* has been ported. Not just that, the Linux backend can even do
cross-architecture injection like we do on the other platforms. This means a
64-bit Frida process, e.g. your Python interpreter, can inject into a 32-bit
process. The other direction works too.

Another awesome update is that [Tyilo](https://github.com/Tyilo) contributed
[improvements](https://github.com/frida/frida-python/commit/daf1a310670588e5672af2205658598be342c2e2)
to *frida-trace* so it now uses man-pages for auto-generating the log handlers.
Awesome, huh? But there's even more goodies:

- *frida-server* ports are now recycled, so if you're using Frida on Android
  you won't have to keep forwarding ports unless you're actually attaching to
  multiple processes at the same time.
- Linux and Android `spawn()` support has been improved to also support PIE
  binaries.
- Android stability and compatibility improvements.
- Mac and Linux build system have been revamped, and make it easy to build just
  the parts that you care about; and maybe even some components you didn't even
  know were there that were previously not built by default.
- Python bindings have a minor simplification so instead of
  `frida.attach(pid).session.create_script()` it's simply just
  `frida.attach(pid).create_script()`. This is just like in the brand
  new Node.js bindings, and the reason we had to bump the major version.

That's the gist of it. Please help spread the word by sharing this post across
the inter-webs. We're still quite small as an open source project, so
word-of-mouth marketing means a lot to us.

Enjoy!
