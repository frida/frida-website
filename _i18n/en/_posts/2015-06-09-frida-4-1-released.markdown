---
layout: news_item
title: 'Frida 4.1 Released'
date: 2015-06-09 09:00:00 +0100
author: oleavr
version: 4.1
categories: [release]
---

It's release o'clock, and this time we're taking the iOS support to the next
level while also bringing some solid quality improvements. I'm also really
excited to announce that I've recently joined [NowSecure](https://www.nowsecure.com/),
and the awesomeness of this release is no conincidence.

Let's start with a brand new iOS feature. It's now possible to list installed
apps, which *frida-ps* can do for you:

{% highlight sh %}
$ frida-ps -U -a
  PID NAME        IDENTIFIER
10582 Facebook    com.facebook.Facebook
11066 IRCCloud    com.irccloud.IRCCloud
  451 Mail        com.apple.mobilemail
10339 Mailbox     com.orchestra.v2
 6866 Messages    com.apple.MobileSMS
10626 Messenger   com.facebook.Messenger
11043 Settings    com.apple.Preferences
10542 Skype       com.skype.skype
11218 Slack       com.tinyspeck.chatlyio
11052 Snapchat    com.toyopagroup.picaboo
$
{% endhighlight %}

Add the `-i` switch and it will also include all installed applications, and
not just those of them that are currently running.

This is also available from your language binding of choice, e.g. from Python:

{% highlight python %}
>>> import frida
>>> iphone = frida.get_usb_device()
>>> print("\n".join(map(repr, iphone.enumerate_applications())))
Application(identifier="com.google.ios.youtube", name="YouTube")
Application(identifier="com.toyopagroup.picaboo", name="Snapchat")
Application(identifier="com.skype.skype", name="Skype", pid=10542)
…
>>>
{% endhighlight %}

That's cool, but wouldn't you like to do early instrumentation of those apps?
Now you can do that too, by just asking us to spawn an app identifier:

{% highlight sh %}
$ frida-trace -U -f com.toyopagroup.picaboo -I "libcommonCrypto*"
{% endhighlight %}

Or at the API level:

{% highlight python %}
>>> import frida
>>> iphone = frida.get_usb_device()
>>> pid = iphone.spawn(["com.toyopagroup.picaboo"])
>>> snapchat = iphone.attach(pid)
>>> …apply instrumentation…
>>> iphone.resume(pid)
{% endhighlight %}

Note that we piggy-back on *Cydia Substrate* for the early launch part in order
to maximize interoperability; after all it's not too good if multiple frameworks
all inject code into *launchd* and risk stepping on each others' toes. This
dependency is however a soft one, so we'll throw an exception if Substrate isn't
installed when trying to call `spawn()` with an app identifier.

So, early instrumentation of iOS apps is pretty cool. But, those applications
are typically consuming tons of Objective-C APIs, and if we want to instrument
them we often find ourselves having to create new Objective-C classes in order
to create delegates to insert between the application and the API. Wouldn't it
be nice if such Objective-C classes could be created in pure JavaScript? Now
they can:

{% highlight js %}
const MyConnectionDelegateProxy = ObjC.registerClass({
  name: 'MyConnectionDelegateProxy',
  super: ObjC.classes.NSObject,
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    '- init': function () {
      const self = this.super.init();
      if (self !== null) {
        ObjC.bind(self, {
          foo: 1234
        });
      }
      return self;
    },
    '- dealloc': function () {
      ObjC.unbind(this.self);
      this.super.dealloc();
    },
    '- connection:didReceiveResponse:': function (conn, resp) {
      /* this.data.foo === 1234 */
    },
    /*
     * But those previous methods are declared assuming that
     * either the super-class or a protocol we conform to has
     * the same method so we can grab its type information.
     * However, if that's not the case, you would write it
     * like this:
     */
    '- connection:didReceiveResponse:': {
      retType: 'void',
      argTypes: ['object', 'object'],
      implementation: function (conn, resp) {
      }
    },
    /* Or grab it from an existing class: */
    '- connection:didReceiveResponse:': {
      types: ObjC.classes
          .Foo['- connection:didReceiveResponse:'].types,
      implementation: function (conn, resp) {
      }
    },
    /* Or from an existing protocol: */
    '- connection:didReceiveResponse:': {
      types: ObjC.protocols.NSURLConnectionDataDelegate
          .methods['- connection:didReceiveResponse:'].types,
      implementation: function (conn, resp) {
      }
    },
    /* Or write the signature by hand if you really want to: */
    '- connection:didReceiveResponse:': {
      types: 'v32@0:8@16@24',
      implementation: function (conn, resp) {
      }
    }
  }
});

const proxy = MyConnectionDelegateProxy.alloc().init();
/* use `proxy`, and later: */
proxy.release();
{% endhighlight %}

Though most of the time you'd like to build a proxy object where you
pass on everything and only do some logging for the few methods you
actually care about. Check this out:

{% highlight js %}
const MyConnectionDelegateProxy = ObjC.registerProxy({
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    '- connection:didReceiveResponse:': function (conn, resp) {
      /* fancy logging code here */
      /* this.data.foo === 1234 */
      this.data.target
          .connection_didReceiveResponse_(conn, resp);
    },
    '- connection:didReceiveData:': function (conn, data) {
      /* other logging code here */
      this.data.target
          .connection_didReceiveData_(conn, data);
    }
  },
  events: {
    forward: function (name) {
      console.log('*** forwarding: ' + name);
    }
  }
});

const method = ObjC.classes.NSURLConnection[
    '- initWithRequest:delegate:startImmediately:'];
Interceptor.attach(method.implementation, {
  onEnter(args) {
    args[3] = new MyConnectionDelegateProxy(args[3], {
      foo: 1234
    });
  }
});
{% endhighlight %}

So that's Objective-C. The Dalvik integration also got some sweet new API for
enumerating loaded classes thanks to [@marc1006](https://github.com/marc1006),
who also fixed our handling of static methods and being able to return booleans
from overriden implementations.

We also got lots of awesome improvements from [@Tyilo](https://github.com/Tyilo)
who helped improve the ObjC integration, beat the REPL into better shape, added
APIs for enumerating malloc ranges, and added some convenience APIs to
*NativePointer*.

While all of this was going on, [@s1341](https://github.com/s1341) has been
hard at work doing an amazing job porting Frida to QNX, which is now really
close to working like a charm.

Let's run through the remaining changes:

4.0.1:

- objc: support for more types
- frida-trace: fix ObjC tracing regression

4.0.2:

- frida-node: fix encoding of the *pixels* property

4.0.3:

- frida-repl: fix Windows regression

4.0.5:

- objc: support for more types and better type checking
- objc: arm64 now working properly
- frida-repl: allow variables to be created

4.0.6:

- platform: support passing a plain array of data to *send()*
- arm: support for relocating *cbz*/*cbnz* instructions

4.1.0:

- platform: fix spawning of child processes that write to stdout
- platform: fix NativeCallback's handling of *bool*/*int8*/*uint8* return
  values (this was preventing Dalvik method overrides from being able to
  return *false*).
- platform: allow *Memory.readByteArray()* with length < 1
- arm: support for relocating the *ldrpc t2* instruction
- arm: improved redirect resolver
- arm64: fix relocation of the *adrp* instruction
- arm64: support for relocating PC-relative *ldr* instruction
- dalvik: add *Dalvik.enumerateLoadedClasses()*
- dalvik: fix handling of static methods
- python: fix *console.log()* on Windows
- frida-repl: bugfixes and improvements
- frida-trace: glob support for tracing ObjC methods

4.1.1:

- platform: add missing pid field in *enumerate_applications()*

4.1.2:

- objc: class and proxy creation APIs
- objc: new *ObjC.protocols* API for enumerating protocols

4.1.3:

- platform: improved concurrency by releasing V8 lock while calling
  NativeFunction
- platform: add *Process.getModuleByName(name)*
- platform: faster and more robust detach
- python: stability improvements in CLI tools
- frida-repl: replace *readline* with *prompt-toolkit*

4.1.4:

- platform: faster and more robust teardown
- frida-server: clean up on *SIGINT* and *SIGTERM*

4.1.5:

- frida-ps: add support for listing applications

4.1.6:

- platform: fix crash on spawn on Mac, iOS and Linux
- platform: add *NativePointer.compare()* and *NativePointer.equals()*
- platform: add *Process.enumerateMallocRanges{,Sync}()*
- frida-trace: switch from Enter to Ctrl+C for stopping
- frida-trace: fix spawning of iOS apps
- frida-repl: add prototype names to autocomplete

4.1.7:

- python: CLI tools stability improvements

That's all for now. Please help spread the word by sharing this post across
the inter-webs. We're still quite small as an open source project, so
word-of-mouth marketing means a lot to us.

Enjoy!
