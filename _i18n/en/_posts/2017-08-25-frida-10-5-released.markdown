---
layout: news_item
title: 'Frida 10.5 Released'
date: 2017-08-25 04:00:00 +0200
author: oleavr
version: 10.5
categories: [release]
---

The midnight oil has been burning and countless cups of coffee have been
consumed here at [NowSecure][], and boy do we have news for you this time.

Continuing in the spirit of last release' low-level bag of goodies, we'll be
moving one level up the stack this time. We are going to introduce a brand new
way to use new CodeWriter APIs, enabling you to weave in your own instructions
into the machine code executed by any thread of your choosing. We're talking
lazy dynamic recompilation on a per-thread basis, with precise control of the
compilation process.

But first a little background. Most people using Frida are probably using the
[Interceptor][] API to perform inline hooking, and/or doing method swizzling or
replacement through the [ObjC][] and [Java][] APIs. The idea is typically to
modify some interesting API that you expect to be called, and be able to divert
execution to your own code in order to observe, augment, or fully replace
application behavior.

One drawback to such approaches is that code or data is modified, and such
changes can be trivially detected. This is fine though, as being invisible to
the hosting process' own code is always going to be a cat and mouse game when
doing in-process instrumentation.

These techniques are however quite limited when trying to answer the question
of "behind this private API, which other APIs actually get called for a given
input?". Or, when doing reversing and fuzzing, you might want to know where
execution diverges between two known inputs to a given function. Another example
is measuring code coverage. You could use Interceptor's support for
instruction-level probes, first using a static analysis tool to find all the
basic blocks and then using Frida to put single-shot probes all over the place.

Enter Stalker. It's not a new API, but it's been fairly limited in what it
allowed you to do. Think of it as a per-thread code-tracer, where the thread's
original machine code is dynamically recompiled to new memory locations in
order to weave in instrumentation between the original instructions.

It does this recompilation lazily, one basic-block at a time. Considering that
a lot of self-modifying code exists, it is careful about caching compiled blocks
in case the original code changes after the fact.

Stalker also goes to great lengths to recompile the code such that
side-effects are identical. E.g. if the original instruction is a CALL it will
make sure that the address of the original next instruction is what's pushed on
the stack, and not the address of the next recompiled instruction.

Anyway, Stalker has historically been like a pet project inside of a pet
project. A lot of fun, but other parts of Frida received most of my attention
over the years. There have been some awesome exceptions though. Me and
[@karltk][] did some [fun pair-programming sessions][] many years ago when we
sat down and decided to get Stalker working well on hostile code. At some
later point I put together [CryptoShark][] in order get people excited about its
potential. Some time went by and suddenly Stalker received a critical bug-fix
contributed by [Eloi Vanderbeken]. Early this year, [Antonio Ken Iannillo][]
jumped on board and ported it to arm64. Then, very recently, [Erik Smit][]
showed up and fixed a critical bug where we would produce invalid code for
REP-prefixed JCC instructions. Yay!

Stalker's API has so far been really limited. You can tell it to follow a
thread, including the thread you're in, which is useful in combination with
inline hooking, i.e. Interceptor. The only two things you could do was:

1. Tell it which events you're interested in, e.g. `call: true`, which will
   produce one event per CALL instruction. This means Stalker will add some
   logging code before each such instruction, and that would log where the
   CALL happened, its target, and its stack depth. The other event types are
   very similar.
2. Add your own call probes for specific targets, giving you a synchronous
   callback into JavaScript when a CALL is made to a specific target.

I'm super-excited to announce that we've just introduced a third thing you
can do with this API, and this one is a game changer. You can now customize
the recompilation process, and it's really easy:

{% highlight js %}
var appModule = Process.enumerateModulesSync()[0];
var appStart = appModule.base;
var appEnd = appStart.add(appModule.size);

Process.enumerateThreadsSync().forEach(function (thread) {
  console.log('Stalking ' + thread.id);

  Stalker.follow(thread.id, {
    transform: function (iterator) {
      var instruction = iterator.next();

      var startAddress = instruction.address;
      var isAppCode = startAddress.compare(appStart) >= 0 &&
          startAddress.compare(appEnd) === -1;

      do {
        if (isAppCode && instruction.mnemonic === 'ret') {
          iterator.putCmpRegI32('eax', 60);
          iterator.putJccShortLabel('jb', 'nope', 'no-hint');

          iterator.putCmpRegI32('eax', 90);
          iterator.putJccShortLabel('ja', 'nope', 'no-hint');

          iterator.putCallout(onMatch);

          iterator.putLabel('nope');
        }

        iterator.keep();
      } while ((instruction = iterator.next()) !== null);
    }
  });
});

function onMatch (context) {
  console.log('Match! pc=' + context.pc +
      ' rax=' + context.rax.toInt32());
}
{% endhighlight %}

The `transform` callback gets called synchronously whenever a new basic block
is about to be compiled. It gives you an iterator that you then use to drive
the recompilation-process forward, one instruction at a time. The returned
[Instruction][] tells you what you need to know about the instruction that's
about to be recompiled. You then call `keep()` to allow Stalker to recompile
it as it normally would. This means you can omit this call if you want to skip
some instructions, e.g. because you've replaced them with your own code. The
iterator also allows you to insert your own instructions, as it exposes the full
CodeWriter API of the current architecture, e.g. [X86Writer][].

The example above determines where the application's own code is in memory, and
adds a few extra instructions before every RET instruction in any code belonging
to the application itself. This code checks if `eax` contains a value between 60
and 90, and if it does, calls out to JavaScript to let it implement arbitrarily
complex logic. This callback can read and modify registers as it pleases.
What's nice about this approach is that you can insert code into hot code-paths
and selectively call into JavaScript, making it easy to do really fast checks in
machine code but offload more complex tasks to a higher level language. You can
also `Memory.alloc()` and have the generated code write directly there, without
entering into JavaScript at all.

So that's the big new thing in 10.5. Special thanks to [@asabil] who helped
shape this new API.

In closing, the only other big change is that the Instruction API now exposes
a lot more details of the underlying [Capstone][] instruction. Stalker also
uses a lot less memory on both x86 and arm64, and is also more reliable. Lastly,
[Process.setExceptionHandler()][] is now a documented API, along with our
[SQLite API][].

Enjoy!

[NowSecure]: https://www.nowsecure.com/
[Interceptor]: /docs/javascript-api/#interceptor
[ObjC]: /docs/javascript-api/#objc
[Java]: /docs/javascript-api/#java
[@asabil]: https://twitter.com/asabil
[@karltk]: https://twitter.com/karltk
[fun pair-programming sessions]: http://blog.kalleberg.org/post/833101026/live-x86-code-instrumentation-with-frida
[CryptoShark]: https://www.youtube.com/watch?v=hzDsxtcRavY
[Eloi Vanderbeken]: https://twitter.com/elvanderb
[Antonio Ken Iannillo]: https://twitter.com/AKIannillo
[Erik Smit]: https://github.com/erik-smit
[Instruction]: /docs/javascript-api/#instruction
[X86Writer]: /docs/javascript-api/#x86writer
[Capstone]: http://www.capstone-engine.org/
[Process.setExceptionHandler()]: /docs/javascript-api/#process
[SQLite API]: https://frida.re/docs/javascript-api/#sqlitedatabase
