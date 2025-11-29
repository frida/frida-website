要为 macOS 设置 Frida，您需要授权 Frida 使用 task_for_pid 来访问您的目标进程。

如果您通过 GUI 使用本地用户运行 Frida 工具（例如从 Terminal.app），系统将通过 taskgate 提示您授权该进程。

您可能还需要禁用 [系统完整性保护](https://support.apple.com/en-us/HT204899)。

### Objective-C 基础

{% highlight py %}
import frida
import sys

def on_message(message, data):
    print("[{}] => {}".format(message, data))

def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script("""
        const appWillFinishLaunching = ObjC.classes.NSApplicationDelegate['- applicationWillFinishLaunching:'];
        Interceptor.attach(appWillFinishLaunching.implementation, {
          onEnter(args) {
            // As this is an Objective-C method, the arguments are as follows:
            // 0. 'self'
            // 1. The selector (applicationWillFinishLaunching:)
            // 2. The first argument to this method
            const notification = new ObjC.Object(args[2]);

            // Convert it to a JS string and log it
            const notificationStr = notification.absoluteString().toString();
            console.log('Will finish launching with notification: ' + notificationStr);
          }
        });
    """)
    script.on("message", on_message)
    script.load()
    print("[!] Ctrl+D or Ctrl+Z to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()


if __name__ == "__main__":
    main("Safari")
{% endhighlight %}
