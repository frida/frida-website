---
layout: docs
title: Android
prev_section: ios
next_section: frida-cli
permalink: /docs/android/
---

In this tutorial we show how to do function tracing on your Android device.

## Setting up your Android device

Before you start, you will need to root your device in case you haven't done so
already. You will also need the Android SDK so you can use the `adb` tool. This
is a stop-gap solution and won't be necessary once Frida has an Android app
(pull-request welcome!).

First off, download the latest `frida-server` for Android:
{% highlight bash %}
$ curl -O http://build.frida.re/frida/android/arm/bin/frida-server
$ chmod +x frida-server
{% endhighlight %}

Next, deploy `frida-server` on your device:
{% highlight bash %}
$ adb push frida-server /data/local/tmp/
{% endhighlight %}

## Spin up Frida

In one terminal (on your desktop), run the server:
{% highlight bash %}
$ adb shell
root@android:/ # /data/local/tmp/frida-server
{% endhighlight %}

While that's running, forward some local TCP ports to your device:
{% highlight bash %}
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043
{% endhighlight %}

*27042* is the port used for communicating with `frida-server`, and each
subsequent port is required for each of the next processes you inject into.

Now, just to verify things are working:
{% highlight bash %}
$ frida-ps -R
{% endhighlight %}

Should give you a process list along the lines of:

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
$ frida-trace -R -i open com.android.chrome
Uploading data...
open: Auto-generated handler …/linker/open.js
open: Auto-generated handler …/libc.so/open.js
Started tracing 2 functions. Press ENTER to stop.
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

While the CLI tools like *frida-trace*, *frida-repl*, etc., are definitely
quite useful, there might be times when you'd like to build your own tools
harnessing the powerful [Frida APIs](/docs/javascript-api/). For that we would
recommend reading the chapters on [Functions](/docs/functions) and
[Messages](/docs/messages), and anywhere you see `frida.attach()` just
substitute that with `frida.get_remote_device().attach()`.
