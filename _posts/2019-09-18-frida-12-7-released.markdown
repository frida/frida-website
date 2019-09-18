---
layout: news_item
title: 'Frida 12.7 Released'
date: 2019-09-18 23:00:00 +0200
author: oleavr
version: 12.7
categories: [release]
---

There's only one new feature this time, but it's a big one. We're going to
address the elephant in the room: performance.

While Frida's instrumentation core, Gum, is written in C and can be used from C,
most use-cases are better off using its JavaScript bindings.

There are however situations where performance becomes an issue. Even when using
our V8-based runtime, which means your JavaScript will be profiled while it's
running and optimized based on where the hotspots are... (Which by the way is
amazing – V8 is truly an impressive feat of engineering!)

...there is a small price to pay for entering and leaving the JavaScript VM.
On an iPhone 5S this might amount to something like six microseconds if you
use *Interceptor.attach()* and only specify *onEnter*, and leave it empty.

This may not sound like a lot, but if a function is called a million times,
it's going to amount to 6 seconds of added overhead. And perhaps the hook only
needs to do something really simple, so most of the time is actually spent on
entering and leaving the VM.

There's also the same kind of issue when needing to pass a callback to an API,
where the API walks through potentially millions of items and needs to call the
callback for each of them. The callback might just look at one byte and collect
the few of the items that match a certain criteria.

Naively one could go ahead and use a NativeCallback to implement that callback,
but it quickly becomes apparent that this just doesn't scale.

Or, you might be writing a fuzzer and needing to call a NativeFunction in a
tight loop, and the cost of entering/leaving the VM plus libffi just adds up.

Short of writing the whole agent in C, one could go ahead and build a native
library, and load it using *Module.load()*. This works but means it has to be
compiled for every single architecture, deployed to the target, etc.

Another solution is to use the X86Writer/Arm64Writer/etc. APIs to generate
code at runtime. This is also painful as there's quite a bit of work required
for each architecture to be supported. But up until now this was the only
portable option for use in modules such as [frida-java-bridge][].

But now we finally have something much better. Enter **CModule**:

![CModule Hello World](/img/cmodule-hello-world.png "CModule Hello World")

It takes the string of C source code and compiles it to machine code, straight
to memory. This is implemented using [TinyCC][], which means that this feature
only adds ~100 kB of footprint to Frida.

As you can see, any global functions are automatically exported as NativePointer
properties named exactly like in the C source code.

And, it's fast:

![CModule Speed](/img/cmodule-speed.png "CModule Speed")

(Measured on an Intel i7 @ 3.1 GHz.)

We can also use this new feature in conjunction with APIs like Interceptor:

{% highlight js %}
const m = new CModule(`
#include <gum/guminterceptor.h>

#define EPERM 1

int
open (const char * path,
      int oflag,
      ...)
{
  GumInvocationContext * ic;

  ic = gum_interceptor_get_current_invocation ();
  ic->system_error = EPERM;

  return -1;
}
`);

const openImpl = Module.getExportByName(null, 'open');

Interceptor.replace(openImpl, m.open);
{% endhighlight %}

(Note that this and the following examples use modern JavaScript features like
template literals, so they either need to be run on our V8 runtime, or compiled
using [frida-compile][].)

We can also combine it with *Interceptor.attach()*:

{% highlight js %}
const openImpl = Module.getExportByName(null, 'open');

Interceptor.attach(openImpl, new CModule(`
  #include <gum/guminterceptor.h>
  #include <stdio.h>

  void
  onEnter (GumInvocationContext * ic)
  {
    const char * path;

    path = gum_invocation_context_get_nth_argument (ic, 0);

    printf ("open() path=\\"%s\\"\\n", path);
  }

  void
  onLeave (GumInvocationContext * ic)
  {
    int fd;

    fd = (int) gum_invocation_context_get_return_value (ic);

    printf ("=> fd=%d\\n", fd);
  }
`));
{% endhighlight %}

Yay. Though this last particular example actually writes to *stdout* of the
target process, which is fine for debugging but probably not all that useful.

We can however fix that by calling back into JavaScript. Let's see what that
might look like:

{% highlight js %}
const openImpl = Module.getExportByName(null, 'open');

Interceptor.attach(openImpl, new CModule(`
  #include <gum/guminterceptor.h>

  extern void onMessage (const gchar * message);

  static void log (const gchar * format, ...);

  void
  onEnter (GumInvocationContext * ic)
  {
    const char * path;

    path = gum_invocation_context_get_nth_argument (ic, 0);

    log ("open() path=\\"%s\\"", path);
  }

  void
  onLeave (GumInvocationContext * ic)
  {
    int fd;

    fd = (int) gum_invocation_context_get_return_value (ic);

    log ("=> fd=%d", fd);
  }

  static void
  log (const gchar * format,
       ...)
  {
    gchar * message;
    va_list args;

    va_start (args, format);
    message = g_strdup_vprintf (format, args);
    va_end (args);

    onMessage (message);

    g_free (message);
  }
`, {
  onMessage: new NativeCallback(messagePtr => {
    const message = messagePtr.readUtf8String();
    console.log('onMessage:', message);
  }, 'void', ['pointer'])
}));
{% endhighlight %}

That is however just a toy example: doing it this way will actually defeat the
purpose of writing the hooks in C to improve performance. A real implementation
might instead append to a [GLib.Array][] after acquiring a [GLib.Mutex][], and
periodically flush the buffered data by calling back into JS.

And just like JavaScript functions can be called from C, we can also share data
between the two realms:

{% highlight js %}
const calls = Memory.alloc(4);

const openImpl = Module.getExportByName(null, 'open');

Interceptor.attach(openImpl, new CModule(`
  #include <gum/guminterceptor.h>

  extern volatile gint calls;

  void
  onEnter (GumInvocationContext * ic)
  {
    g_atomic_int_add (&calls, 1);
  }
`, { calls }));

setInterval(() => {
  console.log('Calls so far:', calls.readInt());
}, 1000);
{% endhighlight %}

For now we don't have any docs on the built-in C APIs, but you can browse the
headers in [frida-gum/bindings/gumjs/runtime/cmodule][] to get an overview.
Drop function names into an Internet search engine to look up docs for the
non-Frida APIs such as GLib's.

The intention is to only expose a minimal subset of the standard C library,
GLib, JSON-GLib, and Gum APIs; in order to minimize bloat and maximize
performance. Things we include should either be impossible to achieve by calling
into JS, or prohibitively expensive to achieve that way.

Think of the JS side as the operating system where the functions you plug into
it are system calls; and only use CModule for hooking hot functions or
implementing high-performance glue code like callbacks passed to
performance-sensitive APIs.

Also bear in mind that the machine code generated by TinyCC is not as efficient
as that of Clang or GCC, so computationally expensive algorithms might actually
be faster to implement in JavaScript. (When using our V8-based runtime.) But for
hooks and glue code this difference isn't significant, and you can always
generate machine code using e.g. Arm64Writer and plug into your CModule if you
need to optimize an inner loop.

One important caveat is that all data is read-only, so writable globals should
be declared *extern*, allocated using e.g. *Memory.alloc()*, and passed in as
symbols through the constructor's second argument. (Like we did with `calls` in
the last example.)

You might also need to initialize things and clean them up when the CModule gets
destroyed – e.g. because the script got unloaded – and we provide a couple of
lifetime hooks for such purposes:

{% highlight js %}
const cm = new CModule(`
#include <stdio.h>

void
init (void)
{
  printf ("init\\n");
}

void
finalize (void)
{
  printf ("finalize\\n");
}
`);

cm.dispose(); // or wait until it gets GCed or script unloaded
{% endhighlight %}

Anyway, this post is getting long, but before we wrap up let's look at how to
use CModule with the Stalker APIs:

{% highlight js %}
const cm = new CModule(`
#include <gum/gumstalker.h>

static void on_ret (GumCpuContext * cpu_context,
    gpointer user_data);

void
transform (GumStalkerIterator * iterator,
           GumStalkerWriter * output,
           gpointer user_data)
{
  cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->id == X86_INS_RET)
    {
      gum_x86_writer_put_nop (output);
      gum_stalker_iterator_put_callout (iterator,
          on_ret, NULL, NULL);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
on_ret (GumCpuContext * cpu_context,
        gpointer user_data)
{
  printf ("on_ret!\n");
}
`);

const mainThread = Process.enumerateThreads()[0];

Stalker.follow(mainThread.id, {
  transform: cm.transform,
  data: ptr(1337)
});
{% endhighlight %}

This shows how you can implement both the transform callback and the callouts
in C, but you may also use a hybrid approach where you write the transform
callback in JS and only some of the callouts in C.

It is also worth noting that I rewrote *ObjC.choose()* to use CModule, and it is
now roughly 100x faster. When testing it on the login screen of the Twitter app
on an iPhone 6S, this went from taking ~5 seconds to now only ~50 ms.

So with that, I hope you'll enjoy this release. Excited to see what kind of
things you will build with the new CModule API. One thing I'm really looking
forward to is improving our REPL to support loading a *.c* file next to the
*.js*, for rapid prototyping purposes.

Enjoy!


### Changes in 12.7.0

- Brand new CModule API powered by TinyCC. (You just read about it.)
- TinyCC was improved to support Apple's ABI on macOS/x86.
- *Stalker.exclude()* is now exposed to JS to be able to mark specific memory
  ranges as excluded. This is useful to improve performance and reduce noise.
- Concurrent calls to *Java.use()* are now supported, thanks to a neat
  contribution by [gebing][].
- The *hexdump()* implementation was improved to clamp the *length* option to
  the length of the ArrayBuffer, thanks to another neat contribution by
  [gebing][].

### Changes in 12.7.1

- More CModule goodies, including [GLib.String][], [GLib.Timer][], and
  [Json.Builder][].
- TinyCC was improved to support Apple's ABI on iOS/arm64.
- *ObjC.choose()* was rewritten using CModule, and is now ~100x faster.

### Changes in 12.7.2

- CModule got some missing ref-counting APIs.

### Changes in 12.7.3

- CModule memory ranges are now properly cloaked.
- The V8 garbage collector is now informed about externally allocated CModule
  memory so it can make better decisions about when to GC.
- Symbols attached to a CModule are now properly kept alive in the V8 runtime
  also; and the CModule itself is not kept alive indefinitely (or until script
  unload).
- *CModule.dispose()* was added for eagerly cleaning up memory.


[frida-java-bridge]: https://github.com/frida/frida-java-bridge
[TinyCC]: https://bellard.org/tcc/
[frida-compile]: https://github.com/oleavr/frida-agent-example
[GLib.Array]: https://developer.gnome.org/glib/stable/glib-Arrays.html
[GLib.Mutex]: https://developer.gnome.org/glib/stable/glib-Threads.html#GMutex
[frida-gum/bindings/gumjs/runtime/cmodule]: https://github.com/frida/frida-gum/tree/master/bindings/gumjs/runtime/cmodule
[gebing]: https://github.com/gebing
[GLib.String]: https://developer.gnome.org/glib/stable/glib-Strings.html
[GLib.Timer]: https://developer.gnome.org/glib/stable/glib-Timers.html
[Json.Builder]: https://developer.gnome.org/json-glib/stable/JsonBuilder.html
