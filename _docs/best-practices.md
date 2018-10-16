---
layout: docs
title: Best practices
permalink: /docs/best-practices/
---

## Best Practices

This section is meant to contain best practices and pitfalls found during the
usage of `frida`. 

### Strings allocation (ANSI/UTF8)

By reading the documentation, one might think that allocating/replacing strings 
could be as simple as:

{% highlight javascript %}
onEnter: function(args) {
  // In case, args is an Ansi string (Windows only)
  Memory.writeAnsiString(ptr(args[0]), 'mystring');
}
{% endhighlight %}

However, this is not possible due to different reasons including writting to 
Read-Only sections and duktape's garbage collector freeing NativePointer's 
before expected.

Therefore, a reliable way to do this asignment would be:

{% highlight javascript %}
onEnter: function(args) {
  var foo = Memory.allocAnsiString('mystring');
  this.foo = foo;
  args[0] = foo; // We can now assign foo to args[0] safely.

  console.log(Memory.readAnsiString(args[0]));
}
{% endhighlight %}
