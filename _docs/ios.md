---
layout: docs
title: iOS
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

Now, back on your Windows or macOS system it's time to make sure the basics
are working. Run:

{% highlight bash %}
$ frida-ps -U
{% endhighlight %}

<div class="note info">
  <h5>Using a Linux-based OS?</h5>
  <p>
    As of Frida 6.0.9 there's now usbmuxd integration, so -U works.
    For earlier Frida versions you can use WiFi and set up an SSH
    tunnel between localhost:27042 on both ends, and then use -R instead
    of -U.
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
$ frida-trace -U -i "CCCryptorCreate*" Twitter
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

In order to instrument an app with Frida you will need to make it load a .dylib
that we'll refer to as a "gadget".

In this tutorial we will show you how to change your Xcode build configuration
so you can start instrumenting your app with Frida. Note that it is also
possible to perform this on an existing binary by using [insert_dylib](https://github.com/Tyilo/insert_dylib)
or a similar tool.

### Customizing your Xcode project

Download the latest `FridaGadget.dylib` for iOS and sign it:

{% highlight bash %}
$ mkdir Frameworks
$ cd Frameworks
$ curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
$ security find-identity -p codesigning -v
  1) A30E15162B3EB979D2572783BF3… "Developer ID Application: …"
  2) E18BA16DF86318F0ECA4BE17C03… "iPhone Developer: …"
     2 valid identities found
$ codesign -f -s E18BA16DF86318F0ECA4BE17C03… FridaGadget.dylib
FridaGadget.dylib: replacing existing signature
{% endhighlight %}

Open your project in Xcode and drag the "Frameworks" directory from the previous
step into the Project Navigator view, dropping it right next to your
"AppDelegate" source file. It's important that you drag the directory and not
the file. Xcode will then prompt you "Choose options for adding these files:",
and you should then enable the "Copy items if needed" option, and make sure that
"Create folder references" is selected. Hit Finish. Select the project itself
at the top of the Project Navigator view and switch to its "Build Phases" tab.
Expand the "Frameworks" directory in the Project Navigator and drag and drop
`FridaGadget.dylib` into the "Link Binary With Libraries" section. Verify that
the `Frameworks` directory with this .dylib also got added to the
"Copy Bundle Resources" section.

### A quick smoke-test

Launch your app with Xcode, and you should see a message getting logged:

{% highlight text %}
Frida: Listening on TCP port 27042
{% endhighlight %}

Note that the app will appear to "hang" during startup. This is normal and
caused by Frida waiting for you to instrument any APIs you're interested in,
or just tell it to go ahead and finish launching the app.

Now that Frida is waiting for us, and its gadget exposes the same interface
as `frida-server`, we should be able to get a process listing:

{% highlight bash %}
$ frida-ps -U
 PID NAME
 892 Gadget
$
{% endhighlight %}

However unlike `frida-server`, there's only a single process we can attach to,
which is the app itself.

Let's also check which apps can be spawned:

{% highlight bash %}
$ frida-ps -Uai
PID  Name    Identifier
---  ------  ---------------
892  Gadget  re.frida.Gadget
$
{% endhighlight %}

Looking good. If we now `attach()` to this process it will cause the app
to finish launching. However, if we first `spawn(["re.frida.Gadget"])` we will
be able to `attach()` and apply our instrumentation, and the app will not carry
on launching until we call `resume()`. This means we can `attach()` right away
for late instrumentation, or we can `spawn()` to perform early instrumentation.

### Tracing libc calls

Assuming your app was just launched by Xcode and is waiting for you to let it
finish launching, go ahead and try out some early instrumentation:

{% highlight bash %}
$ frida-trace -U -f re.frida.Gadget -i "open*"
Instrumenting functions...
openlog: Auto-generated handler at …/openlog.js
opendev: Auto-generated handler at …/opendev.js
opendir: Auto-generated handler at …/opendir.js
openpty: Auto-generated handler at …/openpty.js
openx_np: Auto-generated handler at …/openx_np.js
open: Auto-generated handler at …/open.js
open$NOCANCEL: Auto-generated handler at …/open_NOCANCEL.js
open_dprotected_np: Auto-generated handler at …/open_dprotected_np.js
openat: Auto-generated handler at …/openat.js
openat$NOCANCEL: Auto-generated handler at …/openat_NOCANCEL.js
openbyid_np: Auto-generated handler at …/openbyid_np.js
Started tracing 11 functions. Press Ctrl+C to stop.
           /* TID 0xb07 */
   193 ms  open(path=0x1988c4669, oflag=0x0, ...)
   194 ms  open(path=0x16fdeebc6, oflag=0x0, ...)
   195 ms  opendir()
   195 ms     | open$NOCANCEL()
   195 ms  opendir()
   196 ms     | open$NOCANCEL()
{% endhighlight %}

You can now live-edit the aforementioned JavaScript files as you read
`man open`, and start diving deeper and deeper into your iOS apps.

### Using the Simulator

To instrument an app running in the Simulator simply replace `-U` with `-R`
in the CLI examples above, and at the API level instead of `get_usb_device()`
use `get_remote_device()`.

## Building your own tools

While the CLI tools like *frida*, *frida-trace*, etc., are definitely
quite useful, there might be times when you'd like to build your own tools
harnessing the powerful [Frida APIs](/docs/javascript-api/). For that we would
recommend reading the chapters on [Functions](/docs/functions) and
[Messages](/docs/functions), and anywhere you see `frida.attach()` just
substitute that with `frida.get_usb_device().attach()`.
