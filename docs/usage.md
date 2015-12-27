---
layout: docs
title: Basic Usage
prev_section: installation
next_section: modes
permalink: /docs/usage/
---

The Python API for Frida is fairly high-level and for the time being quite
limited. It should be taken as an example at what you might build on top of
the more flexible Frida Core APIs. We advise you to read the source code in
[frida/core.py](https://github.com/frida/frida-python/blob/master/src/frida/core.py)
and [frida/tracer.py](https://github.com/frida/frida-python/blob/master/src/frida/tracer.py)
to dig deeper into the details.

## Enumerating Modules

The `enumerate_modules()` method lists all modules (mostly shared/dynamic
libraries) currently loaded in the target process' session `s`.

Running:
{% highlight py %}
print(s.enumerate_modules())
{% endhighlight %}

should give you something like:

{% highlight py %}
[Module(name="cat", base_address=0x400000, size=20480, path="/bin/cat"), ...]
{% endhighlight %}

where `base_address` is the base address of the module.

## Enumerating Memory Ranges

The `enumerate_ranges(mask)` method lists all memory ranges currently mapped
by the target process' session `s`.

Running:

{% highlight py %}
print s.enumerate_ranges('rw-')
{% endhighlight %}

should give you something like:

{% highlight py %}
[Range(base_address=0x2d4160a06000, size=1019904, protection='rwx'), ...]
{% endhighlight %}

where `base_address` is the base address of that range. The `enumerate_ranges()`
method requires a protection mask on the form `rwx` where `-` can be taken to
mean any (wildcard).

## Reading/Writing Memory

The `read_bytes(address, n)` method reads `n` bytes from `address` in the target
process' session `s`. The `write_bytes(address, data)` method writes the bytes
in data (a raw Python string) to `address`.

Running:

{% highlight py %}
print s.read_bytes(49758817247232, 10).encode("hex")
{% endhighlight %}

should give you some binary data, e.g.:

{% highlight py %}
454c4602010100000000
{% endhighlight %}

Running:

{% highlight py %}
s.write_bytes(49758817247232, "frida")
{% endhighlight %}

should return after it has updated the memory in the target process.
