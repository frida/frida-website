---
layout: docs
title: frida-trace
permalink: /docs/frida-trace/
---

frida-trace is a tool for dynamically tracing function calls.

{% highlight bash %}
# Trace recv* and send* APIs in Safari, insert library names
# in logging
$ frida-trace --decorate -i "recv*" -i "send*" Safari

# Trace ObjC method calls in Safari
$ frida-trace -m "-[NSView drawRect:]" Safari

# Launch SnapChat on your iPhone and trace crypto API calls
$ frida-trace -U -f com.toyopagroup.picaboo -I "libcommonCrypto*"

# Trace all JNI functions in Samsung FaceService app on Android
$ frida-trace -U -i "Java_*" com.samsung.faceservice

# Trace a Windows process's calls to "mem*" functions in msvcrt.dll
$ frida-trace -p 1372 -i "msvcrt.dll!*mem*"

# Trace all functions matching "*open*" in the process except
# in mscvrt.dll
$ frida-trace -p 1372 -i "*open*" -x "msvcrt.dll!*open*"

# Trace an unexported function in libjpeg.so
$ frida-trace -p 1372 -a "libjpeg.so!0x4793c"
{% endhighlight %}

## Full List of Options

{% highlight bash %}
--version             show program's version number and exit
-h, --help            show this help message and exit
-D ID, --device=ID    connect to device with the given ID
-U, --usb             connect to USB device
-R, --remote          connect to remote frida-server
-H HOST, --host=HOST  connect to remote frida-server on HOST
-f FILE, --file=FILE  spawn FILE
-F, --attach-frontmost
                      attach to frontmost application
-n NAME, --attach-name=NAME
                      attach to NAME
-p PID, --attach-pid=PID
                      attach to PID
--stdio=inherit|pipe  stdio behavior when spawning (defaults to "inherit")
--runtime=duk|v8      script runtime to use (defaults to "duk")
--debug               enable the Node.js compatible script debugger
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
-M OBJC_METHOD, --exclude-objc-method=OBJC_METHOD
                      exclude OBJC_METHOD
-s DEBUG_SYMBOL, --include-debug-symbol=DEBUG_SYMBOL
                      include DEBUG_SYMBOL
-q, --quiet           do not format output messages
-d, --decorate        Add module name to generated onEnter log statement
-o OUTPUT, --output=OUTPUT
                      dump messages to file
{% endhighlight %}

## -U, --usb: connect to USB device

This option tells `frida-trace` to perform tracing on a remote device 
connected via the host machine's USB connection.

Example: You want to trace an application running on an Android device
from your host Windows machine.  If you specify `-U / --usb`, 
frida-trace will perform the necessary work to transfer all data to 
and from the remote device and trace accordingly.

<div class="note">
  <h5>Copy frida-server binary to remote device</h5>
  <p>When tracing a remote device, remember to copy the 
  <a href="https://github.com/frida/frida/releases">platform-appropriate frida-server binary</a>
  to the remote device.  Once copied, be sure to run the frida-server binary before
  beginning the tracing session.</p>
  <p>For example, to trace a remote Android application, you would copy the 
  'frida-server-12.8.0-android-arm' binary to the Android's /data/local/tmp 
  folder.  Using adb shell, you would run the server in the background 
  (e.g. frida-server-12.8.0-android-arm &).</p>
</div>

## -I, -X: include/exclude module

These options allow you to include or exclude **all** functions in a particular 
module (e.g., *.so, *.dll) in one, single option.  The option expects a regular
expression for matching one or more modules.  Any module that matches the
regular expression will either be included or excluded in its entirety.

`frida-trace` will generate a JavaScript handler file for each function matched
by the `-I` option.

To exclude specific functions after including an entire module, see the `-i` option.

## -i, -x: include/exclude function (given name)

These options enable you to include or exclude matching functions according to 
your needs.  This is a flexible option, allowing a granularity ranging from 
**all** functions in **all** modules down to a single function in a specific module.

`frida-trace` will generate a JavaScript handler file for each function matched 
by the `-i` option.

The `-i / -x` options differ syntactically from their uppercase counterparts 
in that they accept any of the following forms (MODULE and FUNCTION are
regular expressions):

<pre style="font-family: monospace;">
- MODULE!FUNCTION
- FUNCTION
- !FUNCTION
- MODULE!
</pre>

Here are some examples and their descriptions:

<table style="background-color:white">
  <thead>
    <tr style="background-color:LightSkyBlue; color:White">
      <th style="text-align: left">Option Value</th>
      <th style="text-align: left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align: left; font-family: monospace;">-i "msvcrt.dll!*cpy*"</td>
      <td style="text-align: left">Matches all functions with 'cpy' in its name, only in msvcrt.dll</td>
    </tr>
    <tr>
      <td style="text-align: left; font-family: monospace;">-i "*free*"</td>
      <td style="text-align: left">Matches all functions with 'free' in its name in ALL modules</td>
    </tr>
    <tr>
      <td style="text-align: left; font-family: monospace;">-i "!*free*"</td>
      <td style="text-align: left">Identical to -i "*free*"</td>
    </tr>
    <tr>
      <td style="text-align: left; font-family: monospace;">-i "gdi32.dll!"</td>
      <td style="text-align: left">Trace all functions in gdi32.dll</td>
    </tr>
  </tbody>
  </table>

## -a: include function (given offset)

This option enables tracing functions whose names are not exported by their 
modules (e.g., a static C/C++ function).  This should not prevent you from 
tracing such functions, so long as you know that absolute offset of the
function's entry point.

Example: `-a "libjpeg.so!0x4793c"`

The option value provides both the full name of the module and the hex offset
of the function entry point within the module.

`frida-trace` will generate a JavaScript handler file for each function matched
by the `-a` option.

## -d, --decorate: add module name to log tracing

The `--decorate` option is relevant when `frida-trace` auto-generates JavaScript
handler scripts.  By default, a handler's `onEnter` function looks like this:

<code>onEnter: function (log, args, state) {
  log('memcpy()');
},
</code>

The drawback is that, if there are multiple modules containing the same function 
name, it will be difficult to differentiate between traces.  The `--decorate` 
function instructs `frida-trace` to insert the module name in the default
`onEnter` trace instruction:

<code>onEnter: function (log, args, state) {
  log('memcpy() [msvcrt.dll]');
},
</code>
