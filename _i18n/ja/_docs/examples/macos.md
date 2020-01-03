---
layout: docs
title: macOS
permalink: /docs/examples/macos/
---

To setup Frida for macOS, you need to authorize Frida to use task_for_pid to access your target process.

If you run your Frida tool via the GUI with your local user (e.g. from Terminal.app), you will be prompted via taskgate to authorize the process.

You may also need to disable [System Integrity Protection](https://support.apple.com/en-us/HT204899).

### Objective-C basics

{% highlight py %}
import frida
import sys

def on_message(message, data):
    print("[{}] => {}".format(message, data))

def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script("""
        var appWillFinishLaunching = ObjC.classes.NSApplicationDelegate['- applicationWillFinishLaunching:'];
        Interceptor.attach(appWillFinishLaunching.implementation, {
          onEnter: function (args) {
            // As this is an Objective-C method, the arguments are as follows:
            // 0. 'self'
            // 1. The selector (applicationWillFinishLaunching:)
            // 2. The first argument to this method
            var notification = new ObjC.Object(args[2]);

            // Convert it to a JS string and log it
            var notificationStr = notification.absoluteString().toString();
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
