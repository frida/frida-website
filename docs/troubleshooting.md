---
layout: docs
title: Troubleshooting
prev_section: javascript-api
next_section: building
permalink: /docs/troubleshooting/
---

If you ever run into problems installing or using Frida, here's a few tips
that might be of help. If the problem you’re experiencing isn’t covered below,
please [report an issue]({{ site.repository }}/frida-website/issues/new) so the
Frida community can make everyone’s experience better.

## Could not find suitable distribution for Requirement.parse('frida')

Installing Frida with `easy_install` results in:

{% highlight text %}
Searching for frida
Reading https://pypi.python.org/simple/frida/
No local packages or download links found for frida
error: Could not find suitable distribution for Requirement.parse('frida')
{% endhighlight %}

This appears on some OS X systems where there are multiple versions of
`easy_install` present. A workaround seems to be to force using the
system-provided default, i.d. `sudo /usr/bin/easy_install frida` or
`/usr/bin/easy_install --user frida`.

## No distributions at all found for frida

Running `pip install frida` gives the error
<pre>Could not find any downloads that satisfy the requirement frida</pre>

This is a known issue. Frida is distributed as an `.egg`. You must use
`easy_install` instead of `pip` to install Frida:
 * System-wide: `sudo easy_install frida`.
 * Current user only: `easy_install --user frida`.
 * Or using [virtualenv](http://www.virtualenv.org/en/latest/) .

## ValueError: ambiguous name; it matches:

This means the process name you specified in `frida.attach()` matches more than
one process. You can use the PID instead:

{% highlight py %}
p = frida.attach(12345)
{% endhighlight %}

## SystemError: attach_to_process PTRACE_ATTACH failed: 1

This (probably) means that you don't have permissions to attach to the target
process. The process may be owned by another user and you are not root. You may
have forgotten to enable ptrace of non-child processes. Try:

{% highlight bash %}
sudo sysctl kernel.yama.ptrace_scope=0
{% endhighlight %}

## ImportError: dynamic module does not define init function (init_frida)

This or another similar error message is seen when trying to use `frida-python`
compiled for python 2.x in python 3.x, or vice versa. Check which python
interpreter you are running against which `PYTHONPATH` / `sys.path` is used.
