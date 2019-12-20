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
# in msvcrt.dll
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
module (e.g., *.so, *.dll) in one, single option.  The option expects a filename
glob for matching one or more modules.  Any module that matches the glob pattern
will be either included or excluded in its entirety.

`frida-trace` will generate a JavaScript handler file for each function matched
by the `-I` option.

To exclude specific functions after including an entire module, see the `-i` option.

## -i, -x: include/exclude function (glob-based)

These options enable you to include or exclude matching functions according to 
your needs.  This is a flexible option, allowing a granularity ranging from 
**all** functions in **all** modules down to a single function in a specific module.

`frida-trace` will generate a JavaScript handler file for each function matched 
by the `-i` option.

The `-i / -x` options differ syntactically from their uppercase counterparts 
in that they accept any of the following forms (MODULE and FUNCTION are both
glob patterns):

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
      <td style="text-align: left">Matches all functions with 'cpy' in its name, ONLY in msvcrt.dll</td>
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

<div class="note info">
  <h5>frida-trace's working set and the order of inclusions and exclusions</h5>
  <p>frida-trace has an internal concept of a "working set", i.e., a set of 
  "module:function" pairs whose handlers will be traced at runtime.  The contents of the
  working set can be changed by an include / exclude command line option 
  (-I / -X / -i / -x).</p>
  <p>It is important to understand that the order of the include / exclude 
  options is important.  Each such option works on the current state of the
  working set, and different orderings of options can lead to 
  different results.  In other words, the include/exclude options are procedural
  (i.e., order counts) rather than simply declarative.</p>
  <p>For example, suppose we want to trace all "str*" and "mem*" functions in
  all modules in a running process.  In our example, these functions are found
  in  three modules: <i>ucrtbase.dll, ntdll.dll, and msvcrt.dll</i>.  To reduce the 
  noise, however, we do not want to trace any functions found in the msvcrt.dll
  module.</p>
  <p>We will describe three different option orders on the command line and 
  show that they produce different results.</p>
  <ul>
    <li><div style="font-family: monospace">-i "str*" -i "mem*" -X "msvcrt.dll"</div></li>
      <ul>
        <li><div style="font-family: monospace">'-i "str*"'</div> matches 80 functions in 3 modules, working set has 80 entries</li>
        <li><div style="font-family: monospace">'-i "mem*"'</div> matches 18 functions in 3 modules, working set has 98 entries</li>
        <li><div style="font-family: monospace">'-X "msvcrt.dll"'</div> removes the 28 "str" and 6 "mem" functions originating in 
        msvcrt.dll, <b>final working set has 64 entries</b>.</li>
      </ul>
    <li><div style="font-family: monospace">-i "str*" -X "msvcrt.dll" -i "mem*"</div></li>
      <ul>
        <li><div style="font-family: monospace">'-i "str*"'</div> matches 80 functions in 3 modules, working set has 80 entries</li>
        <li><div style="font-family: monospace">'-X "msvcrt.dll"'</div> removes the 28 "str" functions originating in 
        msvcrt.dll, working set has 52 entries.</li>
        <li><div style="font-family: monospace">'-i "mem*"'</div> matches 18 functions in 3 modules including msvcrt.dll, <b>
        final working set has 70 entries</b></li>
      </ul>
    <li><div style="font-family: monospace">-X "msvcrt.dll" -i "str*" -i "mem*"</div></li>
      <ul>
        <li><div style="font-family: monospace">'-X "msvcrt.dll"'</div> tries to remove the 28 "str" and 6 "mem" functions originating in 
        msvcrt.dll.  Since the working set is empty, there is nothing to remove, working set has 0 entries.</li>
        <li><div style="font-family: monospace">'-i "str*"'</div> matches 80 functions in 3 modules, working set has 80 entries</li>
        <li><div style="font-family: monospace">'-i "mem*"'</div> matches 18 functions in 3 modules, <b>final working set has 98 entries</b></li>
      </ul>
  </ul>
</div>

## -a: include function (offset-based)

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

The drawback is that, if the same function name exists in multiple modules, 
it will be difficult to differentiate between function traces.  The `--decorate` 
function instructs `frida-trace` to insert the module name in the default
`onEnter` trace instruction:

<code>onEnter: function (log, args, state) {
  log('memcpy() [msvcrt.dll]');
},
</code>
