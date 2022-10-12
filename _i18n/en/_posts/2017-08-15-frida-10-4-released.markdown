---
layout: news_item
title: 'Frida 10.4 Released'
date: 2017-08-15 23:00:00 +0200
author: oleavr
version: 10.4
categories: [release]
---

Frida provides quite a few building blocks that make it easy to do portable
instrumentation across many OSes and architectures. One area that's been lacking
has been in non-portable use-cases. While we did provide some primitives like
*Memory.alloc(Process.pageSize)* and *Memory.patchCode()*, making it possible to
allocate and modify in-memory code, there wasn't anything to help you actually
generate code. Or copy code from one memory location to another.

Considering that Frida needs to generate and transform quite a bit of machine
code for its own needs, e.g. to implement *Interceptor* and *Stalker*, it should
come as no surprise that we already have C APIs to do these things across six
different instruction set flavors. Initially these APIs were so barebones that I
didn't see much value in exposing them to JavaScript, but after many years of
interesting internal use-cases they've evolved to the point where the essential
bits are now covered pretty well.

So with 10.4 we are finally exposing all of these APIs to JavaScript. It's also
worth mentioning that these new bindings are auto-generated, so future additions
will be effortless.

Let's take a look at an example on x86:

{% highlight js %}
const getLivesLeft = Module.getExportByName('game-engine.so',
    'get_lives_left');
const maxPatchSize = 64; // Do not write out of bounds, may be
                         // a temporary buffer!
Memory.patchCode(getLivesLeft, maxPatchSize, code => {
  const cw = new X86Writer(code, { pc: getLivesLeft });
  cw.putMovRegU32('eax', 9999);
  cw.putRet();
  cw.flush();
});
{% endhighlight %}

Which means we replaced the beginning of our target function with simply:

{% highlight nasm %}
mov eax, 9999
ret
{% endhighlight %}

I.e. assuming the return type is `int`, we just replaced the function body with
`return 9999;`.

As a side-note you could also use *Memory.protect()* to change the page
protection and then go ahead and write code all over the place, but
*Memory.patchCode()* is very handy because it also

- ensures CPU caches are flushed;
- takes care of code-signing corner-cases on iOS.

So that was a simple example. Let's try something a bit crazier:

{% highlight js %}
const multiply = new NativeCallback(function (a, b) {
  return a * b;
}, 'int', ['int', 'int']);

const impl = Memory.alloc(Process.pageSize);

Memory.patchCode(impl, 64, code => {
  const cw = new X86Writer(code, { pc: impl });

  cw.putMovRegU32('eax', 42);

  const stackAlignOffset = Process.pointerSize;
  cw.putSubRegImm('xsp', stackAlignOffset);

  cw.putCallAddressWithArguments(multiply, ['eax', 7]);

  cw.putAddRegImm('xsp', stackAlignOffset);

  cw.putJmpShortLabel('done');

  cw.putMovRegU32('eax', 43);

  cw.putLabel('done');
  cw.putRet();

  cw.flush();
});

const f = new NativeFunction(impl, 'int', []);
console.log(f());
{% endhighlight %}

Though that's quite a few hoops just to multiply *42* by *7*, the idea is to
illustrate how calling functions, even back into JavaScript, and jumping to
labels, is actually quite easy.

Finally, let's look at how to copy instructions from one memory location to
another. Doing this correctly is typically a lot more complicated than a
straight *memcpy()*, as some instructions are position-dependent and need to
be adjusted based on their new locations in memory. Let's look at how we can
solve this with Frida's new relocator APIs:

{% highlight js %}
const impl = Memory.alloc(Process.pageSize);

Memory.patchCode(impl, Process.pageSize, code => {
  const cw = new X86Writer(code, { pc: impl });

  const libcPuts = Module.getExportByName(null, 'puts');
  const rl = new X86Relocator(libcPuts, cw);

  while (rl.readOne() !== 0) {
    console.log('Relocating: ' + rl.input.toString());
    rl.writeOne();
  }

  cw.flush();
});

const puts = new NativeFunction(impl, 'int', ['pointer']);
puts(Memory.allocUtf8String('Hello!'));
{% endhighlight %}

We just made our own replica of *puts()* in just a few lines of code. Neat!

Note that you can also insert your own instructions, and use *skipOne()* to
selectively skip instructions in case you want to do custom instrumentation.
(This is how Stalker works.)

Anyway, that's the gist of it. You can find the brand new API references at:

- x86
  * [X86Writer](/docs/javascript-api/#x86writer)
  * [X86Relocator](/docs/javascript-api/#x86relocator)
- arm
  * [ArmWriter](/docs/javascript-api/#armwriter)
  * [ArmRelocator](/docs/javascript-api/#armrelocator)
  * [ThumbWriter](/docs/javascript-api/#thumbwriter)
  * [ThumbRelocator](/docs/javascript-api/#thumbrelocator)
- arm64
  * [Arm64Writer](/docs/javascript-api/#arm64writer)
  * [Arm64Relocator](/docs/javascript-api/#arm64relocator)
- mips
  * [MipsWriter](/docs/javascript-api/#mipswriter)
  * [MipsRelocator](/docs/javascript-api/#mipsrelocator)

Also note that *Process.arch* is convenient for determining which
writer/relocator to use. On that note you may wonder why there's just a single
implementation for 32- and 64-bit x86. The reason is that these instruction sets
are so close that it made sense to have a unified implementation. This also
makes it easier to write somewhat portable code, as some meta register-names are
available. E.g. `xax` resolves to `eax` vs `rax` depending on the kind of
process you are in.

Enjoy!
