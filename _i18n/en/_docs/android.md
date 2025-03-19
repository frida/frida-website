In this tutorial we show how to do function tracing on your Android device.

## Setting up your Android device

Before you start, you will need to root your device in case you haven't done so
already. It is technically also possible to use Frida without rooting your
device, for example by repackaging the app to include frida-gadget, or using a
debugger to accomplish the same. But, for this introduction we're going to focus
on the simplest case: a rooted device.

Also note that most of our recent testing has been taking place on a Pixel 3
running Android 9. Older ROMs may work too, but if you're running into basic
issues like Frida crashing the system when launching an app, this is due to
ROM-specific quirks. We cannot test on all possible devices, so we count on
your help to improve on this. However if you're just starting out with Frida it
is strongly recommended to go for a Pixel or Nexus device running the latest
official software, or a device whose software is as close to AOSP as possible.
Another option is using an emulator, ideally with a Google-provided Android 9
emulator image for arm or arm64. (x86 may work too but has gone through
significantly less testing.)

You will also need the `adb` tool from the Android SDK.

First off, download the latest `frida-server` for Android from our [releases
page](https://github.com/frida/frida/releases) and uncompress it.

{% highlight bash %}
$ adb shell getprop ro.product.cpu.abilist # check your device cpu type

$ unxz frida-server.xz
{% endhighlight %}

Now, let's get it running on your device:

{% highlight bash %}
$ adb root # might be required
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "/data/local/tmp/frida-server &"
{% endhighlight %}

Some apps might be able to detect the frida-server location. Renaming the
frida-server binary to a random name, or moving it to another location
such as /dev may do the trick.

For the last step, make sure you start frida-server as root, i.e. if you are
doing this on a rooted device, you might need to *su* and run it from that
shell.

<div class="note info">
  <h5>adb on a production build</h5>
  <p>
    If you get <code>adbd cannot run as root in production builds</code> after
    running <code>adb root</code><br>you need to prefix each shell command with
    <code>su -c</code>. For example:
    <code>adb shell "su -c chmod 755 /data/local/tmp/frida-server"</code>
  </p>
</div>

Next, make sure `adb` can see your device:

{% highlight bash %}
$ adb devices -l
{% endhighlight %}

This will also ensure that the adb daemon is running on your desktop, which
allows Frida to discover and communicate with your device regardless of whether
you've got it hooked up through USB or WiFi.

## A quick smoke-test

Now, on your desktop it's time to make sure the basics are working. Run:

{% highlight bash %}
$ frida-ps -U
{% endhighlight %}

This should give you a process list along the lines of:

{% highlight bash %}
  PID NAME
 1590 com.facebook.katana
13194 com.facebook.katana:providers
12326 com.facebook.orca
13282 com.twitter.android
…
{% endhighlight %}

Great, we're good to go then!

## Tracing open() calls in Chrome

Alright, let's have some fun. Fire up the Chrome app on your device and return
to your desktop and run:

{% highlight bash %}
$ frida-trace -U -i open -N com.android.chrome
Uploading data...
open: Auto-generated handler …/linker/open.js
open: Auto-generated handler …/libc.so/open.js
Started tracing 2 functions. Press Ctrl+C to stop.
{% endhighlight %}

Now just play around with the Chrome app and you should start seeing `open()`
calls flying in:

{% highlight bash %}
1392 ms	open()
1403 ms	open()
1420 ms	open()
{% endhighlight %}

You can now live-edit the aforementioned JavaScript files as you read
`man open`, and start diving deeper and deeper into your Android apps.

## Building your own tools

While the CLI tools like *frida*, *frida-trace*, etc., are definitely
quite useful, there might be times when you'd like to build your own tools
harnessing the powerful [Frida APIs](/docs/javascript-api/). For that we would
recommend reading the chapters on [Functions](/docs/functions) and
[Messages](/docs/messages), and anywhere you see `frida.attach()` just
substitute that with `frida.get_usb_device().attach()`.
