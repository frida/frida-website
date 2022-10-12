---
layout: news_item
title: 'Frida 1.6.0 Released'
date: 2014-05-29 23:00:00 +0100
author: oleavr
version: 1.6.0
categories: [release]
---

As some of you may have noticed, Frida recently got brand new Android support,
allowing you to easily instrument code just like on Windows, Mac, Linux and iOS.
This may sound cool and all, but Android does run a lot of Java code, which
means you'd only be able to observe the native side-effects of whatever
that code was doing. You could of course use Frida's FFI API to poke your way
into the VM, but hey, shouldn't Frida just do that dirty plumbing for you?
Of course it should!

Here's what it looks like in action:

{% highlight js %}
Dalvik.perform(() => {
    const Activity = Dalvik.use('android.app.Activity');
    Activity.onResume.implementation = function () {
        send('onResume() got called! Let's call the original implementation');
        this.onResume();
    };
});
{% endhighlight %}

The `Dalvik.perform()` call takes care of attaching your thread to the VM,
and isn't necessary in callbacks from Java. Also, the first time you call
`Dalvik.use()` with a given class name, Frida will interrogate the VM and
build a JavaScript wrapper on-the-fly. Above we ask for the
[Activity](https://developer.android.com/reference/android/app/Activity.html)
class and replace its implementation of `onResume` with our own version,
and proceed to calling the original implementation after sending a message
to the debugger (running on your Windows, Mac or Linux machine). You could
of course choose to not call the original implementation at all, and emulate
its behavior. Or, perhaps you'd like to simulate an error scenario:

{% highlight js %}
Dalvik.perform(() => {
    const Activity = Dalvik.use('android.app.Activity');
    const Exception = Dalvik.use('java.lang.Exception');
    Activity.onResume.implementation = function () {
        throw Exception.$new('Oh noes!');
    };
});
{% endhighlight %}

So there you just instantiated a Java Exception and threw it straight from
your JavaScript implementation of `Activity.onResume`.

This release also comes with some other runtime goodies:

- `Memory.copy(dst, src, n)`: just like memcpy
- `Memory.dup(mem, size)`: short-hand for `Memory.alloc()` followed by
  `Memory.copy()`
- `Memory.writeXXX()`: the missing `Memory.read()` counterparts: S8, S16, U16,
  S32, U32, S64, U64, ByteArray, Utf16String and AnsiString
- `Process.pointerSize` to make your scripts more portable
- `NativePointer` instances now have a convenient `isNull()` method
- `NULL` constant so you don't have to do `ptr("0")` all over the place
- `WeakRef.bind(value, fn)` and `WeakRef.unbind(id)` for the hardcore:
  The former monitors `value` so `fn` gets called as soon as `value` has been
  garbage-collected, or the script is about to get unloaded. It returns an
  id that you can pass to `unbind()` for explicit cleanup.
  This API is useful if you're building a language-binding, where you need to
  free native resources when a JS value is no longer needed.

Enjoy!
