---
layout: news_item
title: 'Frida 1.6.2 Released'
date: 2014-08-03 17:00:00 +0100
author: oleavr
version: 1.6.2
categories: [release]
---

It's release o'clock, and this time we're bringing you more than just bugfixes.
Meet `Instruction.parse()`:

{% highlight js %}
var a = Instruction.parse(ptr("0x1234"));
var b = Instruction.parse(a.next);
console.log(a);
console.log(b);
{% endhighlight %}

Output:
{% highlight nasm %}
push rbp
mov rbp, rsp
{% endhighlight %}

How is this implemented you ask? That's the cool part. Frida already uses the
amazing [Capstone disassembly framework](http://www.capstone-engine.org/)
behind the scenes, and thus it makes perfect sense to make it available to the
JavaScript runtime. Have a look at the
[JavaScript API Reference](https://www.frida.re/docs/javascript-api/) for all
the details.

Enjoy!
