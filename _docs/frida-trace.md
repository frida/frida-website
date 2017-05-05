---
layout: docs
title: frida-trace
permalink: /docs/frida-trace/
---

frida-trace is a tool for dynamically tracing function calls.

{% highlight bash %}
# Trace recv* and send* APIs in Safari
$ frida-trace -i "recv*" -i "send*" Safari

# Trace ObjC method calls in Safari
$ frida-trace -m "-[NSView drawRect:]" Safari

# Launch SnapChat on your iPhone and trace crypto API calls
$ frida-trace -U -f com.toyopagroup.picaboo -I "libcommonCrypto*"

{% endhighlight %}
Usage: frida-trace [options] target

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -D ID, --device=ID    connect to device with the given ID
  -U, --usb             connect to USB device
  -R, --remote          connect to remote frida-server
  -H HOST, --host=HOST  connect to remote frida-server on HOST
  -f FILE, --file=FILE  spawn FILE
  -n NAME, --attach-name=NAME
                        attach to NAME
  -p PID, --attach-pid=PID
                        attach to PID
  --debug               enable the Node.js compatible script debugger
  --enable-jit          enable JIT
  -I MODULE, --include-module=MODULE
                        include MODULE
  -X MODULE, --exclude-module=MODULE
                        exclude MODULE
  -i FUNCTION, --include=FUNCTION
                        include FUNCTION
  -x FUNCTION, --exclude=FUNCTION
                        exclude FUNCTION
  -a MODULE!OFFSET, --add=MODULE!OFFSET
                        add MODULE!OFFSET
  -T, --include-imports
                        include program's imports
  -t MODULE, --include-module-imports=MODULE
                        include MODULE imports
  -m OBJC_METHOD, --include-objc-method=OBJC_METHOD
                        include OBJC_METHOD
