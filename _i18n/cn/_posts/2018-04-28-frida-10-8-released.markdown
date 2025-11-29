---
layout: news_item
title: 'Frida 10.8 发布'
date: 2018-04-28 06:07:45 +0200
author: oleavr
version: 10.8
categories: [release]
---

准备好迎接重大升级。这次我们解决了三个长期存在的限制 —— 全部在一个版本中。

### 限制 #1: fork()

作为快速复习，这个老派的 UNIX API 克隆整个进程并将子进程的进程 ID 返回给父进程，将零返回给子进程。子进程获得父进程地址空间的副本，由于写时复制，通常成本非常小。

一旦涉及多个线程，处理这个问题就会变得棘手。只有调用 *fork()* 的线程在子进程中存活，所以如果任何其他线程恰好持有锁，这些锁仍将在子进程中持有，并且没有人会释放它们。

本质上，这意味着任何同时进行 fork 和多线程的应用程序都必须真正仔细设计。尽管大多数 fork 的应用程序都是单线程的，但 Frida 通过将 agent 注入其中有效地使它们成为多线程。另一个方面是文件描述符，它们是共享的，因此也必须仔细管理。

我非常兴奋地宣布，我们终于能够检测到 *fork()* 即将发生，暂时停止我们的线程，暂停我们的通信通道，并在之后重新启动。然后，您可以在让子进程继续运行之前，对其应用所需的插桩（如果有）。

### 限制 #2: execve(), posix_spawn(), CreateProcess() 和朋友们

或者用通俗的英语说：启动其他程序的程序，要么完全替换自己，例如 *execve()*，要么通过生成子进程，例如没有 *POSIX_SPAWN_SETEXEC* 的 *posix_spawn()*。

就像 *fork()* 发生后一样，您现在能够应用插桩并控制子进程何时开始运行其第一条指令。

### 限制 #3: 处理突然的进程终止

过去引起很多困惑的一个方面是如何将一些数据传递给 Frida 的 *send()* API，如果进程即将终止，所述数据可能实际上无法到达另一端。

到目前为止，规定的解决方案总是 hook *exit()*、*abort()* 等，这样您就可以做一个 *send()* 加上 *recv().wait()* 乒乓来刷新任何仍在传输中的数据。回想起来，这并不是一个好主意，因为它很难在多个平台上正确执行此操作。我们现在有一个更好的解决方案。

因此，让我们谈谈新的 API 和功能。

### 子进程门控

这就是我们解决前两个问题的方法。提供 *create_script()* 的 *Session* 对象现在也有 *enable_child_gating()* 和 *disable_child_gating()*。默认情况下，Frida 的行为将与以前一样，您必须通过调用 *enable_child_gating()* 来选择加入此新行为。

从那时起，任何子进程最终都会被挂起，您将负责使用其 PID 调用 *resume()*。*Device* 对象现在还提供了一个名为 *delivered* 的信号，您应该附加一个回调以接收任何出现的新子进程的通知。这就是您应该在调用 *resume()* 之前应用所需插桩（如果有）的地方。*Device* 对象还有一个名为 *enumerate_pending_children()* 的新方法，可用于获取挂起子进程的完整列表。进程将保持挂起并作为该列表的一部分，直到它们被您恢复，或最终被杀死。

这就是理论。让我们看一个实际的 [example][]，使用 Frida 的 Python 绑定：

{% highlight python %}
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
        script = session.create_script("""
Interceptor.attach(Module.getExportByName(null, 'open'), {
  onEnter(args) {
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

行动：

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

### 退出前刷新

至于第三个限制，即处理突然的进程终止，Frida 现在将拦截最常见的进程终止 API，并为您处理任何挂起数据的刷新。

但是，对于通过缓冲数据并仅定期执行 *send()* 来优化吞吐量的高级 agent，现在有一种方法可以在进程终止或脚本卸载时运行您自己的代码。您所要做的就是定义一个名为 *dispose* 的 [RPC][] 导出。例如：

{% highlight js %}
rpc.exports = {
  dispose() {
    send(bufferedData);
  }
};
{% endhighlight %}

### 结束语

基于 Frida 中全新的 *fork()* 处理，还有一个完全重做的 Android 应用程序启动实现。*frida-loader-{32,64}.so* 辅助 agent 现在已经消失了，我们的幕后 Zygote 插桩现在利用全新的子进程门控来完成所有繁重的工作。这意味着您也可以根据自己的需要插桩 Zygote。只要记得 *enable_child_gating()* 并 *resume()* 任何您不关心的子进程。

所以这个版本大概就是这样。享受吧！


[example]: https://github.com/frida/frida-python/blob/c846da1191e50e017235f29580c737f5b8555d9a/examples/child_gating.py
[RPC]: /docs/javascript-api/#rpc
