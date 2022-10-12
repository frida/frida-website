---
layout: news_item
title: 'Frida 4.2 Released'
date: 2015-06-18 19:00:00 +0100
author: oleavr
version: 4.2
categories: [release]
---

The Frida co-conspirators have been cracking away on several fronts, so much
lately that I figured it was worth jotting this down to get the word out.

In Dalvik land, [@marc1006](https://github.com/marc1006) contributed a really
neat new feature – the ability to do object carving, essentially scanning the
heap for objects of a certain type. Check this out:

{% highlight js %}
const strings = [];
Dalvik.choose('java.lang.String', {
  onMatch(str) {
    strings.push(str);
  },
  onComplete() {
    console.log('Found ' + strings.length + ' strings!');
  }
});
{% endhighlight %}

Meanwhile, [@Tyilo](https://github.com/Tyilo) has been rocking out adding the
same feature for Objective-C:

{% highlight js %}
const strings = [];
ObjC.choose(ObjC.classes.NSString, {
  onMatch(str) {
    strings.push(str);
  },
  onComplete() {
    console.log('Found ' + strings.length + ' strings!');
  }
});
{% endhighlight %}

In other mobile news, [@pancake](https://github.com/trufae) added support for
enumerating applications on Firefox OS. Sweet!

While all of this was going on, [@s1341](https://github.com/s1341) has been
hard at work stabilizing the QNX port, and it's reportedly working really well
now.

On my end I have been applying Frida to interesting challenges at
[NowSecure](https://www.nowsecure.com/), and ran into quite a few bugs and
limitations in the Objective-C integration. There's now support for overriding
methods that deal with struct types passed by value, e.g. `-[UIView drawRect:]`,
which means `NativeFunction` and `NativeCallback` also support these; so for
declaring a struct simply start an array with the fields' types specified
sequentially. You can even nest them. So for the `- drawRect:` case where a
struct is passed by value, and that struct is made out of two other structs,
you'd declare it like this:

{% highlight js %}
const f = new NativeFunction(ptr('0x1234'), 'void',
    [[['double', 'double'], ['double', 'double']]]);
{% endhighlight %}

Another thing worth mentioning is that a long-standing issue especially visible
when instrumenting 32-bit iOS apps, but affecting all platforms, has finally
[been fixed](https://github.com/frida/frida-gum/commit/2f02e911edc4a5df80051fdaed72e0281ea751e7).

So let's run quickly through all the changes:

4.1.8:

- core: add support for enumerating applications on Firefox OS
- core: add *NativePointer.toMatchPattern()* for use with *Memory.scan()*
- core: fix QNX injector race condition
- objc: massively improved handling of types
- objc: fix implicit conversion from JS string to NSString
- objc: fix crash during registration of second proxy or unnamed class
- objc: new *ObjC.Object* properties: *$className* and *$super*
- dalvik: add *Dalvik.choose()* for object carving

4.1.9:

- core: *NativeFunction* and *NativeCallback* now support functions passing
        struct types by value
- core: fix accidental case-sensitivity in *Process.getModuleByName()*
- dalvik: new object property: *$className*

4.2.0:

- core: add *this.returnAddress* to *Interceptor*'s *onEnter* and *onLeave*
        callbacks
- objc: add *ObjC.choose()* for object carving

4.2.1:

- core: fix exports enumeration of stripped libraries on QNX
- objc: new *ObjC.Object* property: *$kind*, a string that is either *instance*,
        *class* or *meta-class*
- objc: fix the *$class* property so it also does the right thing for classes
- objc: fix crash when looking up inexistent method
- python: ensure graceful teardown of the reactor thread
- frida-discover: fix regression
- frida-repl: fix hang when target crashes during evaluation of expression

4.2.2:

- core: fix exception handling weirdness; very visible on ios-arm
- core: QNX stability improvements
- objc: add *ObjC.api* for direct access to the Objective-C runtime's API
- objc: new *ObjC.Object* properties: *equals*, *$superClass* and *$methods*
- objc: fix iOS 7 compatibility
- objc: fix *toJSON()* of *ObjC.classes* and *ObjC.protocols*
- dalvik: fix handling of *java.lang.CharSequence*
- frida-repl: add *%time* command for easy profiling

4.2.3:

- core: fix crash when handling exceptions without a message object
- core: fix the life-time of CpuContext JS wrappers
- core: expose the file mapping info to *Process.enumerateRanges()*
- core: make it possible to coalesce neighboring ranges when enumerating
- core: add convenience API for looking up modules and ranges
- core: make the QNX mprotect read in a loop instead of just the once
- dalvik: avoid crashing the process if a type conversion fails
- dalvik: allow *null* as call parameter
- objc: fix conversion of structs with simple field types
- objc: speed up implicit string conversion by caching wrapper object

4.2.4:

- objc: fix crash when interacting with not-yet-realized classes

4.2.5:

- core: optimize Interceptor callback logic and make it twice as fast when
        *onEnter* and *onLeave* aren't both specified
- core: fix return-address seen by the invocation-context on arm64
- core: add a fuzzy backtracer for arm64

4.2.6:

- core: fix access to arguments 4 through 7 on arm64
- core: add *Memory.readFloat()*, *Memory.writeFloat()*, *Memory.readDouble()*
        and *Memory.writeDouble()*
- dalvik: improved type checking
- qnx: implement side-stack for calling *onEnter()*/*onLeave()* with the
       stack-hungry V8 engine

4.2.7:

- core: Darwin backend bug-fixes
- core: optimize handling of the *send()* data payload
- core: add APIs for interacting with the iOS kernel through *task_for_pid(0)*,
        only available in the *attach(pid=0)* session
- core: side-stack support for replaced functions on QNX
- objc: add *getOwnPropertyNames()* to ObjC.classes
- frida-repl: improved completion

4.2.8:

- python: fix Py3k regression

4.2.9:

- objc: add *$ownMethods* to *ObjC.Object*
- dalvik: add support for primitive arrays and object arrays
- python: improve compatibility between Python 2 and 3
- frida-repl: better magic commands

4.2.10:

- core: fix Interceptor vector register clobbering issue on arm64
- core: improve temporary directory handling on Android

4.2.11:

- dalvik: add support for accessing instance and static fields
- dalvik: type conversion improvements
- python: resolve python runtime lazily on Mac to allow our binaries to work
          with multiple Python distributions
- python: pip support

4.2.12:

- python: fix Py3k regressions

That's all for now. Please help spread the word by sharing this post across
the inter-webs. We're still quite small as an open source project, so
word-of-mouth marketing means a lot to us.

Enjoy!
