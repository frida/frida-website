---
layout: docs
title: Best Practices
permalink: /docs/best-practices/
---

This section is meant to contain best practices and pitfalls commonly
encountered when using Frida.

### String allocation (UTF-8/UTF-16/ANSI)

By reading the documentation, one might think that allocating/replacing strings
is as simple as:

{% highlight javascript %}
onEnter: function (args) {
  args[0].writeUtf8String('mystring');
}
{% endhighlight %}

However, this may not be possible because the string pointed to may:

- Reside in a "read-only-data" section which gets mapped into the process'
  address space as read-only;
- Be longer than the string already there, so *writeUtf8String()* causes a
  buffer-overflow and may corrupt unrelated memory.

Even if you could solve the former issue by using *Memory.protect()*, there is
a much better solution: allocate a new string and replace the argument instead.

There is however a pitfall: the value returned by *Memory.allocUtf8String()*
must be kept alive -- it gets freed as soon as the JavaScript value gets
garbage-collected. This means it needs to be kept alive for at least the
duration of the function-call, and in some cases even longer; the exact
semantics depend on how the API was designed.

With this in mind, a reliable way to do this would be:

{% highlight javascript %}
onEnter: function (args) {
  var buf = Memory.allocUtf8String('mystring');
  this.buf = buf;
  args[0] = buf;
}
{% endhighlight %}

The way this works is that *this* is bound to an object that is per-thread and
per-invocation, and anything you store there will be available in *onLeave*, and
this even works in case of recursion. This way you can read arguments in
*onEnter* and access them later in *onLeave*. It is also the recommended way to
keep memory allocations alive for the duration of the function-call.

If the function keeps the pointer around and also uses it after the function
call has completed, one solution is to do it like this:

{% highlight javascript %}
var myStringBuf = Memory.allocUtf8String('mystring');

Interceptor.attach(f, {
  onEnter: function (args) {
    args[0] = myStringBuf;
  }
});
{% endhighlight %}
