---
layout: news_item
title: 'Frida 12.10 Released'
date: 2020-06-29 22:00:00 +0200
author: oleavr
version: 12.10
categories: [release]
---

This time we have some exciting news for Java developers and reversers:
[frida-java-bridge][] now supports the HotSpot JVM. This means our Java
runtime bridge is no longer exclusively an Android feature. Huge thanks to
[Razvan Sima][] for this amazing addition.

The timing couldn't have been any better either, as we recently also added
*Java.enumerateMethods(query)*, a brand new API for efficiently locating methods
matching a given query. We made sure to also implement this for the HotSpot JVM.

The query is specified as `"class!method"`, with globs permitted. It may also be
suffixed with `/` and one or more modifiers:

-   `i`: Case-insensitive matching.
-   `s`: Include method signatures, so e.g. `"putInt"` becomes
    `"putInt(java.lang.String, int): void"`. Handy to match on argument and
    return types, such as `"*!*: boolean/s"` to match all methods that return a
    boolean.
-   `u`: User-defined classes only, ignoring system classes.

For instance:

{% highlight js %}
Java.perform(() => {
  const groups = Java.enumerateMethods('*youtube*!on*')
  console.log(JSON.stringify(groups, null, 2));
});
{% endhighlight %}

Which might output something like:

{% highlight json %}
[
  {
    "loader": "<instance: java.lang.ClassLoader, $className: dalvik.system.PathClassLoader>",
    "classes": [
      {
        "name": "com.google.android.apps.youtube.app.watch.nextgenwatch.ui.NextGenWatchLayout",
        "methods": [
          "onAttachedToWindow",
          "onDetachedFromWindow",
          "onFinishInflate",
          "onInterceptTouchEvent",
          "onLayout",
          "onMeasure",
          "onSizeChanged",
          "onTouchEvent",
          "onViewRemoved"
        ]
      },
      {
        "name": "com.google.android.apps.youtube.app.search.suggest.YouTubeSuggestionProvider",
        "methods": [
          "onCreate"
        ]
      },
      {
        "name": "com.google.android.libraries.youtube.common.ui.YouTubeButton",
        "methods": [
          "onInitializeAccessibilityNodeInfo"
        ]
      },
      …
    ]
  }
]
{% endhighlight %}

We've also enhanced frida-trace to support Java method tracing:

{% highlight bash %}
$ frida-trace \
    -U \
    -f com.google.android.youtube \
    --runtime=v8 \
    -j '*!*certificate*/isu'
Instrumenting...
X509Util.addTestRootCertificate: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.X509Util/addTestRootCertificate.js"
X509Util.clearTestRootCertificates: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.X509Util/clearTestRootCertificates.js"
X509Util.createCertificateFromBytes: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.X509Util/createCertificateFromBytes.js"
X509Util.isKnownRoot: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.X509Util/isKnownRoot.js"
X509Util.verifyKeyUsage: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.X509Util/verifyKeyUsage.js"
X509Util.verifyServerCertificates: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.X509Util/verifyServerCertificates.js"
ResourceLoader$CppProxy.native_enableDevCertificate: Auto-generated handler at "/Users/oleavr/__handlers__/com.google.android.libraries.elements.interfaces.ResourceLoader_CppProxy/native_enableDevCertificate.js"
ResourceLoader$CppProxy.enableDevCertificate: Auto-generated handler at "/Users/oleavr/__handlers__/com.google.android.libraries.elements.interfaces.ResourceLoader_CppProxy/enableDevCertificate.js"
AndroidCertVerifyResult.getCertificateChainEncoded: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.AndroidCertVerifyResult/getCertificateChainEncoded.js"
bjbm.a: Auto-generated handler at "/Users/oleavr/__handlers__/bjbm/a.js"
bjbn.a: Auto-generated handler at "/Users/oleavr/__handlers__/bjbn/a.js"
AndroidNetworkLibrary.addTestRootCertificate: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.AndroidNetworkLibrary/addTestRootCertificate.js"
AndroidNetworkLibrary.clearTestRootCertificates: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.AndroidNetworkLibrary/clearTestRootCertificates.js"
AndroidNetworkLibrary.verifyServerCertificates: Auto-generated handler at "/Users/oleavr/__handlers__/org.chromium.net.AndroidNetworkLibrary/verifyServerCertificates.js"
vxr.checkClientTrusted: Auto-generated handler at "/Users/oleavr/__handlers__/vxr/checkClientTrusted.js"
vxr.checkServerTrusted: Auto-generated handler at "/Users/oleavr/__handlers__/vxr/checkServerTrusted.js"
vxr.getAcceptedIssuers: Auto-generated handler at "/Users/oleavr/__handlers__/vxr/getAcceptedIssuers.js"
ResourceLoader.enableDevCertificate: Auto-generated handler at "/Users/oleavr/__handlers__/com.google.android.libraries.elements.interfaces.ResourceLoader/enableDevCertificate.js"
Started tracing 18 functions. Press Ctrl+C to stop.
           /* TID 0x339d */
   955 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,9,…],[48,-126,4,…]], "RSA", "suggestqueries.google.com")
   972 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
  1043 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,4,…],[48,-126,4,…]], "RSA", "www.googleadservices.com")
  1059 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
           /* TID 0x33a0 */
  1643 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,5,…],[48,-126,4,…]], "RSA", "googleads.g.doubleclick.net")
           /* TID 0x339d */
  1651 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,9,…],[48,-126,4,…]], "RSA", "www.youtube.com")
           /* TID 0x33a1 */
  1665 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,15,…],[48,-126,4,…]], "RSA", "lh3.googleusercontent.com")
           /* TID 0x33a0 */
  1674 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
           /* TID 0x339d */
  1674 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
           /* TID 0x3417 */
  1674 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,15,…],[48,-126,4,…]], "RSA", "yt3.ggpht.com")
           /* TID 0x33a1 */
  1684 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
           /* TID 0x3417 */
  1688 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
  2513 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,9,…],[48,-126,4,…]], "RSA", "redirector.googlevideo.com")
  2527 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
  2722 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,9,…],[48,-126,4,…]], "RSA", "r1---sn-bxuovgf5t-vnaz.googlevideo.com")
           /* TID 0x33a1 */
  2741 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,9,…],[48,-126,4,…]], "RSA", "r2---sn-bxuovgf5t-vnas.googlevideo.com")
           /* TID 0x339d */
  2758 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,9,…],[48,-126,4,…]], "RSA", "r2---sn-bxuovgf5t-vnaz.googlevideo.com")
           /* TID 0x33a1 */
  2771 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
           /* TID 0x3417 */
  2772 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
           /* TID 0x339d */
  2777 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
  2892 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,6,…],[48,-126,4,…]], "RSA", "r2---sn-bxuovgf5t-vnas.googlevideo.com")
           /* TID 0x3417 */
  2908 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,6,…],[48,-126,4,…]], "RSA", "r2---sn-bxuovgf5t-vnaz.googlevideo.com")
           /* TID 0x33a1 */
  2926 ms  AndroidNetworkLibrary.verifyServerCertificates([[48,-126,6,…],[48,-126,4,…]], "RSA", "r1---sn-bxuovgf5t-vnaz.googlevideo.com")
           /* TID 0x3417 */
  2935 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
           /* TID 0x339d */
  2937 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
           /* TID 0x33a1 */
  2942 ms  AndroidCertVerifyResult.getCertificateChainEncoded()
{% endhighlight %}

This was just released as part of [frida-tools][] 8.0 – which you may grab
through e.g.: `pip3 install -U frida-tools`

We've also been working hard on quality improvements across the board. One good
example is Stalker for 32-bit ARM, which now works a lot better on Android. It
is also a lot faster, in part because of a bug resulting in Thumb blocks being
recompiled over and over. We have also implemented one of the adaptive
optimizations that the other Stalker backends make use of, and this alone
typically amounts to a ~5x performance improvement.

So that should cover the highlights – but if you're curious about the details
I'd highly recommend reading the changelog below.

Enjoy!


### Changes in 12.10.0

- Java: Add support for HotSpot JVM. Uses JVMTI to enumerate classes and choose
  objects. Method interception works if the JVM library has symbols (default
  with JDK on macOS). Tested on macOS with java 8, 11, 13, 14. Thanks
  [@0xraaz][]!
- Java: Fix non-return from *_getUsedClass()*, where calling *Java.use()* twice
  without using *Java.perform()* would result in *_getUsedClass()* getting stuck
  in an infinite sleep loop. Thanks [@0xraaz][]!
- Java: Fix *$alloc()*, which got broken by the refactoring a while back.
- ObjC: Add *Block.declare()* to be able to work with blocks without signature
  metadata.
- ObjC: Fix ObjC *pointer* handling regression introduced in 12.9.8.

### Changes in 12.10.1

- Java: Allow ClassFactory.get(null), for convenience when using
  enumerateMethods().
- Java: Restore the JVM method adjustment logic, which got accidentally dropped
  from the pull-request. Thanks [@0xraaz][]!

### Changes in 12.10.2

- Fix handling of long symbol names on i/macOS. Thanks [@mrmacete][]!
- Java: Fix JVM interception issues for static/final methods. Thanks
  [@0xraaz][]!
- Fix Stalker ARM handling of Thumb-2 “mov pc, \<reg\>”.
- Fix Stalker ARM handling of volatile VFP registers.

### Changes in 12.10.3

- Fix device removal wiring in the Fruity backend. Thanks [@mrmacete][]!
- Avoid clobbering R9 in *ArmWriter.put_branch_address()*.
- Add *ThumbWriter.can_branch_directly_between()*.
- Add *ThumbWriter.put_branch_address()*.
- Improve ThumbRelocator to handle ADR.
- Fix Stalker ARM block corruption.
- Fix Stalker ARM block recycling logic for Thumb blocks.
- Add missing Stalker ARM continuation logic, to support long basic blocks.
- Implement Stalker ARM backpatching logic to improve performance, typically 5x.

### Changes in 12.10.4

- Fix encoding of *Module.name* in the V8 runtime. Thanks [@mrmacete][]!


[frida-java-bridge]: https://github.com/frida/frida-java-bridge
[Razvan Sima]: https://twitter.com/0xraaz
[frida-tools]: https://github.com/frida/frida-tools
[@0xraaz]: https://twitter.com/0xraaz
[@mrmacete]: https://twitter.com/bezjaje
