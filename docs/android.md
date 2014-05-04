---
layout: docs
title: Android
prev_section: ios
next_section: javascript-api
permalink: /docs/android/
---

In this tutorial we show how to do function tracing on your Android device.

## Setting up your Android device

Before you start, you will need to jailbreak your device in case you haven't
done so already. You will also need the Android SDK so you can use the `adb`
tool. This is a stop-gap solution and won't be necessary once Frida has an
Android app (pull-request welcome!).

First off, download the latest `frida-server` for Android:
{% highlight bash %}
$ curl -O http://build.frida.re/frida/android/bin/frida-server
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
root@android:/ # /data/local/tmp/frida-server -t 0
{% endhighlight %}

While that's running, forward the local TCP port `27042` to your device:
{% highlight bash %}
adb forward tcp:27042 tcp:27042
{% endhighlight %}

Now, just to verify things are working:
{% highlight bash %}
$ frida-ps -R
{% endhighlight %}

You should see a process list along the lines of:

{% highlight bash %}
oles-mbp:frida-python oleavr$ python src/frida/ps.py -R
  PID NAME
 1590 com.facebook.katana
13194 com.facebook.katana:providers
12326 com.facebook.orca
13282 com.twitter.android
…
{% endhighlight %}

Great, we're good to go then!

## Tracing crypto calls in Chrome

Alright, let's have some fun. Fire up the Chrome app on your device and return
to your desktop and run:

{% highlight bash %}
$ frida-trace -R -I libssl.so com.android.chrome
{% endhighlight %}

Boom! ...But that's all for now. More documentation to follow.
