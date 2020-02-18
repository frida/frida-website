This is a command-line tool for listing attached devices, which is very useful
when interacting with multiple devices.

{% highlight bash %}
# Connect Frida to an iPad over USB and list running processes
$ frida-ls-devices

# example output

Id                                        Type    Name
----------------------------------------  ------  ----------------
local                                     local   Local System
0216027d1d6d3a03                          tether  Samsung SM-G920F
1d07b5f6a7a72552aca8ab0e6b706f3f3958f63e  tether  iOS Device
tcp                                       remote  Local TCP


{% endhighlight %}
