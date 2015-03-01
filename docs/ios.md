---
layout: docs
title: iOS
prev_section: messages
next_section: android
permalink: /docs/ios/
---

In this tutorial we show how to do function tracing on your iOS device.

## Setting up your iOS device

First off, you will need to jailbreak your device in case you haven't done so
already. Also, we recommend using iOS 7.x as we haven't performed any recent
regression tests on earlier versions.
Next, start `Cydia` and add Frida's repository by going to `Manage` ->
`Sources` -> `Edit` -> `Add` and enter `http://ospy.org`. You should now
be able to find and install the `Frida` package which lets Frida inject
JavaScript into apps running on your iOS device. This happens over USB,
so you will need to have your USB cable handy, though there's no need to
plug it in just yet.

## A quick smoke-test

Now, back on your Windows or Mac system it's time to make sure the basics
are working. Run:

{% highlight bash %}
$ frida-ps -U
{% endhighlight %}

Unless you already plugged in your device, you should see the following
message:

{% highlight text %}
Waiting for USB device to appear...
{% endhighlight %}

Plug in your device, and you should see a process list along the lines of:

{% highlight bash %}
 PID NAME
 488 Clock
 116 Facebook
 312 IRCCloud
1711 LinkedIn
…
{% endhighlight %}

Great, we're good to go then!

## Tracing crypto calls in the Twitter app

Alright, let's have some fun. Fire up the Twitter app on your device, and while
making sure it stays in the foreground without the device going to sleep, go
back to your desktop and run:

{% highlight bash %}
$ frida-trace -U -i 'CCCryptorCreate*' Twitter
Uploading data...
CCCryptorCreate: Auto-generated handler …/CCCryptorCreate.js
CCCryptorCreateFromData: Auto-generated handler …/CCCryptorCreateFromData.js
CCCryptorCreateWithMode: Auto-generated handler …/CCCryptorCreateWithMode.js
CCCryptorCreateFromDataWithMode: Auto-generated handler …/CCCryptorCreateFromDataWithMode.js
Started tracing 4 functions. Press ENTER to stop.
{% endhighlight %}

Now, `CCryptorCreate` and friends are part of Apple's `libcommonCrypt.dylib`,
and is used by many apps to take care of encryption, decryption, hashing, etc.

Reload your Twitter feed or exercise the UI in some way that results in network
traffic, and you should see some output like the following:

{% highlight bash %}
  3979 ms	CCCryptorCreate()
  3982 ms	CCCryptorCreateWithMode()
  3983 ms	CCCryptorCreate()
  3983 ms	CCCryptorCreateWithMode()
{% endhighlight %}

You can now live-edit the aforementioned JavaScript files as you read
`man CCryptorCreate`, and start diving deeper and deeper into your iOS apps.

## Building your own tool from scratch

While the CLI tools like *frida-trace*, *frida-repl*, etc., are definitely
quite useful, there might be times when you'd like to build your own tool
harnessing the powerful [Frida APIs](/docs/javascript-api/). For that we would
recommend reading the chapters on [Functions](/docs/functions) and
[Messages](/docs/functions), and anywhere you see `frida.attach()` just
substitute that with `frida.get_usb_device().attach()`.
