Getting Frida installed and ready-to-go should only take a few minutes. If it
ever becomes a pain in the ass, please [file an
issue]({{ site.organization_url }}/frida-website/issues/new) (or submit a pull request)
describing the issue you encountered and how we might make the process easier.

### Requirements for Frida's CLI tools

Installing Frida's CLI tools is easy and straight-forward, but there are a few
requirements you’ll need to make sure your system has before you start.

- [Python](https://python.org/) – latest 3.x is highly recommended
- Windows, macOS, or GNU/Linux

## Install with pip

The best way to install Frida's CLI tools is via [PyPI][]:

{% highlight bash %}
$ pip install frida-tools
{% endhighlight %}

If you have problems installing Frida, check out the [troubleshooting][] page or
[report an issue]({{ site.organization_url }}/frida-website/issues/new) so the
Frida community can improve the experience for everyone.

## Install manually

You can also grab other binaries from Frida's GitHub [releases][] page.

## Testing your installation

Start a process we can inject into:

{% highlight bash %}
$ cat
{% endhighlight %}

Just let it sit and wait for input. On Windows you might want to use
`notepad.exe`.

Note that this example won’t work on macOS El Capitan and later, as it rejects
such attempts for system binaries. See [here]({{ site.repository }}/issues/83)
for more details. However, if you copy the `cat` binary to e.g., `/tmp/cat` then
run that instead the example should work:

{% highlight bash %}
$ cp /bin/cat /tmp/cat
$ /tmp/cat
{% endhighlight %}

In another terminal, make a file `example.py` with the following contents:

{% highlight py %}
import frida

def on_message(message, data):
    print("[on_message] message:", message, "data:", data)

session = frida.attach("cat")

script = session.create_script("""
rpc.exports.enumerateModules = () => {
  return Process.enumerateModules();
};
""")
script.on("message", on_message)
script.load()

print([m["name"] for m in script.exports_sync.enumerate_modules()])
{% endhighlight %}

If you are on GNU/Linux, issue:

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
['cat', …, 'ld-2.15.so']
{% endhighlight %}

[PyPI]: https://pypi.python.org/pypi/frida-tools
[troubleshooting]: ../troubleshooting/
[releases]: https://github.com/frida/frida/releases
