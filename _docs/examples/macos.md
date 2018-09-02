---
layout: docs
title: macOS
permalink: /docs/examples/macos/
---

To setup Frida for macOS, you need to authorize Frida to use task_for_pid to access your target process.

If you run your Frida tool via the GUI with your local user (e.g. from Terminal.app), you will be prompted via taskgate to authorize the process.

You may also need to disable [System Integrity Protection](https://support.apple.com/en-us/HT204899).

_Please click "Improve this page" above and add an example. Thanks!_

{% highlight py %}

import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script("""
	// Get a reference to the openURL selector
  var appWillFinishLaunch = ObjC.classes.NSApplicationDelegate["- applicationWillFinishLaunching:"];

  // Intercept the method
  Interceptor.attach(appWillFinishLaunch.implementation, {
    onEnter: function(args) {
      // As this is an ObjectiveC method, the arguments are as follows:
      // 0. 'self'
      // 1. The selector (applicationWillFinishLaunching:)
      // 2. The first argument to the this selector
      var myNotification = new ObjC.Object(args[2]);

      // Convert it to a JS string
      var myJSNotification = myNotification.absoluteString().toString();
      // Log it
      console.log("will finish Launching with notification: " + myJSNotification);
    }
  });
""")
    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D or Ctrl+Z to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main("Safari")
{% end highlight %}
