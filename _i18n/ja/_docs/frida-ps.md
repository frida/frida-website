This is a command-line tool for listing processes, which is very useful
when interacting with a remote system.

You can acquire device id from [frida-ls-devices](/docs/frida-ls-devices) tool.
{% highlight bash %}
# Connect Frida to an iPad over USB and list running processes
$ frida-ps -U

# List running applications
$ frida-ps -Ua

# List installed applications
$ frida-ps -Uai

# Connect Frida to the specific device
$ frida-ps -D 0216027d1d6d3a03

{% endhighlight %}
