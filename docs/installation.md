---
layout: docs
title: Installation
prev_section: quickstart
next_section: usage
permalink: /docs/installation/
---

Getting Frida installed and ready-to-go should only take a few minutes. If it
ever becomes a pain in the ass, please [file an
issue]({{ site.repository }}/frida-website/issues/new) (or submit a pull request)
describing the issue you encountered and how we might make the process easier.

### Requirements

Installing Frida is easy and straight-forward, but there are a few requirements
you’ll need to make sure your system has before you start.

- [Python](http://python.org/)
- [setuptools](https://pypi.python.org/pypi/setuptools)
- Windows, Mac OS X or Linux

<div class="note info">
  <h5>Running Frida on Linux</h5>
  <p>
    While Frida's Linux support is still beta quality, it should work well
    as long as you don't need support for injecting into 32-bit processes.
  </p>
</div>

## Install with easy_install

The best way to install Frida is via
[PyPI](https://pypi.python.org/pypi/frida). At the terminal prompt,
simply run the following command to install Frida:

{% highlight bash %}
$ sudo easy_install frida
{% endhighlight %}

All of Frida’s PyPI dependencies are automatically installed by the above
command, so you won’t have to worry about them at all. If you have problems
installing Frida, check out the [troubleshooting](../troubleshooting/) page or
[report an issue]({{ site.repository }}/frida-website/issues/new) so the Frida
community can improve the experience for everyone.

## Install manually

You can also grab pre-release binaries from [here](http://build.frida.re/frida/).

## Testing your installation

Start a process we can inject into:

{% highlight bash %}
$ cat
{% endhighlight %}

Just let it sit and wait for input. On Windows you might want to use
`notepad.exe`.

In another terminal, make a file example.py with the following contents:

{% highlight py %}
import frida
p = frida.attach("cat")
print([x.name for x in p.enumerate_modules()])
{% endhighlight %}

If you are on Linux, issue:

{% highlight bash %}
$ sudo sysctl kernel.yama.ptrace_scope=0
{% endhighlight %}

to enable ptracing non-child processes.

At this point, we are ready to take Frida for a spin! Run the example.py
script and watch the magic:

{% highlight bash %}
$ python example.py
{% endhighlight %}

The output should be something similar to this (depending on your platform
and library versions):

{% highlight py %}
[u'cat', …, u'ld-2.15.so']
{% endhighlight %}
