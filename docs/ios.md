---
layout: docs
title: iOS
prev_section: messages
next_section: android
permalink: /docs/ios/
---

Frida supports two modes of operation, depending on whether your iOS device
is jailbroken or not.

## Table of contents
  1. [With Jailbreak](#with-jailbreak)
  1. [Without Jailbreak](#without-jailbreak)

## With Jailbreak

This is the most powerful setup, as it lets you instrument system services and
apps with very little effort.

In this tutorial we will show you how to do function tracing on your iOS device.

### Setting up your iOS device

Start `Cydia` and add Frida's repository by going to `Manage` -> `Sources` ->
`Edit` -> `Add` and enter `https://build.frida.re`. You should now be able to
find and install the `Frida` package which lets Frida inject JavaScript into
apps running on your iOS device. This happens over USB, so you will need to have
your USB cable handy, though there's no need to plug it in just yet.

### A quick smoke-test

Now, back on your Windows or Mac system it's time to make sure the basics
are working. Run:

{% highlight bash %}
$ frida-ps -U
{% endhighlight %}

<div class="note info">
  <h5>Using Linux?</h5>
  <p>
    There's not yet any usbmuxd integration, so in the meantime you can use
    WiFi and set up an SSH tunnel between localhost:27042 in both ends, and
    then use -R instead of -U.
  </p>
</div>

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

### Tracing crypto calls in the Twitter app

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
Started tracing 4 functions. Press Ctrl+C to stop.
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

## Without Jailbreak

In order to instrument an app with Frida you will need to link it with a .dylib
provided by Frida.

In this tutorial we will show you how to change your Xcode build configuration
so you can start instrumenting your app with Frida.

### Customizing your Xcode project

Download the latest `FridaGadget.dylib` for iOS:

{% highlight bash %}
$ cd /path/to/your/xcode/project
$ mkdir Frameworks
$ cd Frameworks
$ curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
{% endhighlight %}

Open your project in Xcode and switch to its "Build Phases" tab. Drag and
drop `FridaGadget.dylib` into the "Link Binary With Libraries" section.
Verify that the `Frameworks` directory with this .dylib also got added to
the "Copy Bundle Resources" section.

## Building your own tools

While the CLI tools like *frida*, *frida-trace*, etc., are definitely
quite useful, there might be times when you'd like to build your own tools
harnessing the powerful [Frida APIs](/docs/javascript-api/). For that we would
recommend reading the chapters on [Functions](/docs/functions) and
[Messages](/docs/functions), and anywhere you see `frida.attach()` just
substitute that with `frida.get_usb_device().attach()`.

