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
already. Also note that most of our testing has involved Android 4.4, and while
we do support 4.2 all the way through 6.0, there's for now limited support for
ART and we would recommend that you start out with a Dalvik-powered ARM device
or emulator for the time being.

You will also need the `adb` tool from the Android SDK.

First off, download the latest `frida-server` for Android and get it running
on your device:

{% highlight bash %}
$ curl -O http://build.frida.re/frida/android/arm/bin/frida-server
$ chmod +x frida-server
$ adb push frida-server /data/local/tmp/
$ adb shell "/data/local/tmp/frida-server &"
{% endhighlight %}

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
$ frida-trace -U -i open com.android.chrome
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
