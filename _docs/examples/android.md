---
layout: docs
title: Android
permalink: /docs/examples/android/
---

## Example tool built for an Android CTF

For this particular example, using an Android 4.4 x86 emulator image is highly
recommended. This tool is based on the SECCON Quals CTF 2015 APK1 example,
download the APK [here](https://github.com/ctfs/write-ups-2015/tree/master/seccon-quals-ctf-2015/binary/reverse-engineering-android-apk-1).

Save code as *ctf.py* and run as `python ctf.py`.

{% highlight py %}
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(() => {
  // Function to hook is defined here
  const MainActivity = Java.use('com.example.seccon2015.rock_paper_scissors.MainActivity');

  // Whenever button is clicked
  const onClick = MainActivity.onClick;
  onClick.implementation = function (v) {
    // Show a message to know that the function got called
    send('onClick');

    // Call the original onClick handler
    onClick.call(this, v);

    // Set our values after running the original onClick handler
    this.m.value = 0;
    this.n.value = 1;
    this.cnt.value = 999;

    // Log to the console that it's done, and we should have the flag!
    console.log('Done:' + JSON.stringify(this.cnt));
  };
});
"""

process = frida.get_usb_device().attach('com.example.seccon2015.rock_paper_scissors')
script = process.create_script(jscode)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()
{% endhighlight %}

Note we use `this.m.value = 0` instead of `this.m = 0` to set the field's value.
If there is also a method in this class called `m`, we need to use
`this._m.value = 0` to set the value of field `m`.  In general, when looking at
the properties of objects it will be necessary to use `.value` to access the
values those fields refer to.


## Example of what we can do using the Java bridge

Some possibilities with the Java bridge in Frida:

{% highlight js %}
Java.perform(() => {
  // Create an instance of java.lang.String and initialize it with a string
  const JavaString = Java.use('java.lang.String');
  const exampleString1 = JavaString.$new('Hello World, this is an example string in Java.');
  console.log('[+] exampleString1: ' + exampleString1);
  console.log('[+] exampleString1.length(): ' + exampleString1.length());

  // Create an instance of java.nio.charset.Charset, and initialize the default character set
  const Charset = Java.use('java.nio.charset.Charset');
  const charset = Charset.defaultCharset();
  // Create a byte array of a Javascript string
  const charArray = 'This is a Javascript string converted to a byte array.'.split('').map(function(c) {
    return c.charCodeAt(0);
  });

  // Create an instance of java.lang.String and initialize it through an overloaded $new,
  // with a byte array and a instance of java.nio.charset.Charset
  const exampleString2 = JavaString.$new.overload('[B', 'java.nio.charset.Charset').call(JavaString, charArray, charset)
  console.log('[+] exampleString2: ' + exampleString2);
  console.log('[+] exampleString2.length(): ' + exampleString2.length());

  // Intercept the initialization of java.lang.Stringbuilder's overloaded constructor,
  // and write the partial argument to the console
  const StringBuilder = Java.use('java.lang.StringBuilder');
  // We need to replace .$init() instead of .$new(), since .$new() = .alloc() + .init()
  const ctor = StringBuilder.$init.overload('java.lang.String');
  ctor.implementation = function (arg) {
    let partial = '';
    const result = ctor.call(this, arg);
    if (arg !== null) {
      partial = arg.toString().replace('\n', '').slice(0, 10);
    }
    // console.log('new StringBuilder(java.lang.String); => ' + result);
    console.log('new StringBuilder("' + partial + '");');
    return result;
  };
  console.log('[+] new StringBuilder(java.lang.String) hooked');

  // Intercept the toString() method of java.lang.StringBuilder and write its partial contents to the console.
  const toString = StringBuilder.toString;
  toString.implementation = function () {
    const result = toString.call(this);
    let partial = '';
    if (result !== null) {
      partial = result.toString().replace('\n', '').slice(0, 10);
    }
    console.log('StringBuilder.toString(); => ' + partial);
    return result;
  };
  console.log('[+] StringBuilder.toString() hooked');
});
{% endhighlight %}


## Example of stacktrace usage

{% highlight js %}
Java.perform(() => {
  const Cipher = Java.use('javax.crypto.Cipher');
  const Exception = Java.use('java.lang.Exception');
  const Log = Java.use('android.util.Log');

  const init = Cipher.init.overload('int', 'java.security.Key');
  init.implementation = function (opmode, key) {
    const result = init.call(this, opmode, key);

    console.log('Cipher.init() opmode:', opmode, 'key:', key);
    console.log(stackTraceHere());

    return result;
  };

  function stackTraceHere() {
    return Log.getStackTraceString(Exception.$new());
  }
});
{% endhighlight %}
