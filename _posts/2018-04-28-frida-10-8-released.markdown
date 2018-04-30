---
layout: news_item
title: 'Frida 10.8 Released'
date: 2018-04-28 06:07:45 +0200
author: oleavr
version: 10.8
categories: [release]
---

Get ready for a major upgrade. This time we have solved our three longest
standing limitations, all in one release.

### Limitation #1: fork()

As a quick refresher, this old-school UNIX API clones the entire process and
returns the child's process ID to the parent, and zero to the child. The child
gets its own copy of the parent's address space, usually at a very small cost
due to copy-on-write.

Dealing with this one gets tricky once multiple threads are involved. Only the
thread calling *fork()* survives in the child process, so if any of the other
threads happen to be holding locks, those locks will still be held in the child,
and nobody is going to release them.

Essentially this means that any application doing both forking and
multi-threading will have to be really carefully designed. Even though most
applications that fork are single-threaded, Frida effectively makes them
multi-threaded by injecting its agent into them. Another aspect is
file-descriptors, which are shared, so those also have to be carefully managed.

I'm super-excited to announce that we are finally able to detect that a *fork()*
is about to happen, temporarily stop our threads, pause our communications
channel, and start things back up afterwards. You are then able to apply the
desired instrumentation to the child, if any, before letting it continue
running.

### Limitation #2: execve(), posix_spawn(), CreateProcess, and friends

Or in plain English: programs that start other programs, either by replacing
themselves entirely, e.g. *execve()*, or by spawning a child process, e.g.
*posix_spawn()* without *POSIX_SPAWN_SETEXEC*.

Just like after a *fork()* happened you will now be able to apply
instrumentation and control when the child process starts running its first
instructions.

### Limitation #3: dealing with sudden process termination

An aspect that's caused a lot of confusion in the past is how one might hand off
some data to Frida's *send()* API, and if the process is about to terminate,
said data might not actually make it to the other side.

Up until now the prescribed solution was always to hook *exit()*, *abort()* etc.
so you can do a *send()* plus *recv().wait()* ping-pong to flush any data still
in transit. In retrospect this wasn't such a great idea, as it makes it hard to
do this correctly across multiple platforms. We now have a way better solution.

So with that, let's talk about the new APIs and features.

### Child gating

This is how we address the first two. The *Session* object, the one providing
*create_script()*, now also has *enable_child_gating()* and
*disable_child_gating()*. By default Frida will behave just like before, and
you will have to opt-in to this new behavior by calling *enable_child_gating()*.

From that point on, any child process is going to end up suspended, and you will
be responsible for calling *resume()* with its PID. The *Device* object now also
provides a signal named *delivered* which you should attach a callback to in
order to be notified of any new children that appear. That is the point where
you should be applying the desired instrumentation, if any, before calling
*resume()*. The *Device* object also has a new method named
*enumerate_pending_children()* which can be used to get a full list of pending
children. Processes will remain suspended and part of that list until they're
resumed by you, or eventually killed.

So that's the theory. Let's have a look at a practical example, using Frida's
Python bindings:

{% highlight python %}
from __future__ import print_function
import frida
from frida.application import Reactor
import threading

class Application(object):
    def __init__(self):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda _:
            self._stop_requested.wait())

        self._device = frida.get_local_device()
        self._sessions = set()

        self._device.on("delivered", lambda child:
            self._reactor.schedule(
                lambda: self._on_delivered(child)))

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        argv = ["/bin/sh", "-c", "cat /etc/hosts"]
        print("✔ spawn(argv={})".format(argv))
        pid = self._device.spawn(argv)
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid):
        print("✔ attach(pid={})".format(pid))
        session = self._device.attach(pid)
        session.on("detached", lambda reason:
            self._reactor.schedule(lambda:
                self._on_detached(pid, session, reason)))
        print("✔ enable_child_gating()")
        session.enable_child_gating()
        print("✔ create_script()")
        script = session.create_script("""'use strict';

Interceptor.attach(Module.findExportByName(null, 'open'), {
  onEnter: function (args) {
    send({
      type: 'open',
      path: Memory.readUtf8String(args[0])
    });
  }
});
""")
        script.on("message", lambda message, data:
            self._reactor.schedule(
                lambda: self._on_message(pid, message)))
        print("✔ load()")
        script.load()
        print("✔ resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)

    def _on_delivered(self, child):
        print("⚡ delivered: {}".format(child))
        self._instrument(child.pid)

    def _on_detached(self, pid, session, reason):
        print("⚡ detached: pid={}, reason='{}'"
            .format(pid, reason))
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    def _on_message(self, pid, message):
        print("⚡ message: pid={}, payload={}"
            .format(pid, message["payload"]))


app = Application()
app.run()
{% endhighlight %}

And action:

{% highlight bash %}
$ python3 example.py
✔ spawn(argv=['/bin/sh', '-c', 'cat /etc/hosts'])
✔ attach(pid=42401)
✔ enable_child_gating()
✔ create_script()
✔ load()
✔ resume(pid=42401)
⚡ message: pid=42401,
↪payload={'type': 'open', 'path': '/dev/tty'}
⚡ detached: pid=42401, reason='process-replaced'
⚡ delivered: Child(pid=42401, parent_pid=42401,
↪path="/bin/cat", argv=['cat', '/etc/hosts'],
↪envp=['SHELL=/bin/bash', 'TERM=xterm-256color', …],
↪origin=exec)
✔ attach(pid=42401)
✔ enable_child_gating()
✔ create_script()
✔ load()
✔ resume(pid=42401)
⚡ message: pid=42401,
↪payload={'type': 'open', 'path': '/etc/hosts'}
⚡ detached: pid=42401, reason='process-terminated'
$
{% endhighlight %}

### Flush-before-exit

As for the third limitation, namely dealing with sudden process termination,
Frida will now intercept the most common process termination APIs and take
care of flushing any pending data for you.

However, for advanced agents that optimize throughput by buffering data and only
doing *send()* periodically, there is now a way to run your own code when the
process terminates, or the script is unloaded. All you need to do is to define
an [RPC][] export named *dispose*. E.g.:

{% highlight js %}
rpc.exports = {
  dispose: function () {
    send(bufferedData);
  }
};
{% endhighlight %}

### In closing

Building on the brand new *fork()*-handling in Frida, there is also a fully
reworked Android app launching implementation. The *frida-loader-{32,64}.so*
helper agents are now gone, and our behind-the-scenes Zygote instrumentation
is now leveraging the brand new child gating to do all of the heavy lifting.
This means you can also instrument Zygote for your own needs. Just remember to
*enable_child_gating()* and *resume()* any children that you don't care about.

So that's pretty much it for this release. Enjoy!


[RPC]: /docs/javascript-api/#rpc
