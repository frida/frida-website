---
layout: news_item
title: 'Frida 12.10 发布'
date: 2020-06-29 22:00:00 +0200
author: oleavr
version: 12.10
categories: [release]
---

这次我们为 Java 开发人员和逆向工程师带来了一些令人兴奋的消息：[frida-java-bridge][] 现在支持 HotSpot JVM。这意味着我们的 Java 运行时桥接不再仅仅是 Android 的功能。非常感谢 [Razvan Sima][] 带来的这一惊人补充。

时机也再好不过了，因为我们最近还添加了 *Java.enumerateMethods(query)*，这是一个全新的 API，用于有效地定位与给定查询匹配的方法。我们确保也为 HotSpot JVM 实现了这一点。

查询指定为 `"class!method"`，允许使用通配符。它也可以后缀 `/` 和一个或多个修饰符：

-   `i`: 不区分大小写的匹配。
-   `s`: 包括方法签名，例如 `"putInt"` 变为 `"putInt(java.lang.String, int): void"`。方便匹配参数和返回类型，例如 `"*!*: boolean/s"` 匹配所有返回布尔值的方法。
-   `u`: 仅用户定义的类，忽略系统类。

例如：

{% highlight js %}
Java.perform(() => {
  const groups = Java.enumerateMethods('*youtube*!on*')
  console.log(JSON.stringify(groups, null, 2));
});
{% endhighlight %}

这可能会输出类似的内容：

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

我们还增强了 frida-trace 以支持 Java 方法跟踪：

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

这刚刚作为 [frida-tools][] 8.0 的一部分发布 —— 您可以通过例如 `pip3 install -U frida-tools` 获取。

我们还在努力全面提高质量。一个很好的例子是 32 位 ARM 的 Stalker，它现在在 Android 上工作得更好。它也快得多，部分原因是导致 Thumb 块一遍又一遍地重新编译的错误。我们还实现了其他 Stalker 后端利用的自适应优化之一，仅此一项通常就相当于 ~5 倍的性能提升。

所以这应该涵盖了亮点 —— 但如果您对细节感到好奇，我强烈建议阅读下面的变更日志。

享受吧！


### 12.10.0 中的变化

- Java: 添加对 HotSpot JVM 的支持。使用 JVMTI 枚举类和选择对象。如果 JVM 库具有符号（macOS 上的 JDK 默认具有），则方法拦截有效。在 macOS 上使用 java 8, 11, 13, 14 进行了测试。感谢 [@0xraaz][]！
- Java: 修复 *_getUsedClass()* 不返回的问题，其中在不使用 *Java.perform()* 的情况下调用 *Java.use()* 两次会导致 *_getUsedClass()* 陷入无限睡眠循环。感谢 [@0xraaz][]！
- Java: 修复 *$alloc()*，它被前段时间的重构破坏了。
- ObjC: 添加 *Block.declare()* 以便能够处理没有签名元数据的块。
- ObjC: 修复 12.9.8 中引入的 ObjC *pointer* 处理回归。

### 12.10.1 中的变化

- Java: 允许 ClassFactory.get(null)，为了在使用 enumerateMethods() 时方便。
- Java: 恢复 JVM 方法调整逻辑，该逻辑意外地从拉取请求中删除。感谢 [@0xraaz][]！

### 12.10.2 中的变化

- 修复 i/macOS 上长符号名称的处理。感谢 [@mrmacete][]！
- Java: 修复静态/最终方法的 JVM 拦截问题。感谢 [@0xraaz][]！
- 修复 Stalker ARM 对 Thumb-2 “mov pc, \<reg\>” 的处理。
- 修复 Stalker ARM 对易失性 VFP 寄存器的处理。

### 12.10.3 中的变化

- 修复 Fruity 后端中的设备移除接线。感谢 [@mrmacete][]！
- 避免在 *ArmWriter.put_branch_address()* 中破坏 R9。
- 添加 *ThumbWriter.can_branch_directly_between()*。
- 添加 *ThumbWriter.put_branch_address()*。
- 改进 ThumbRelocator 以处理 ADR。
- 修复 Stalker ARM 块损坏。
- 修复 Thumb 块的 Stalker ARM 块回收逻辑。
- 添加缺失的 Stalker ARM 延续逻辑，以支持长基本块。
- 实现 Stalker ARM 回补逻辑以提高性能，通常为 5 倍。

### 12.10.4 中的变化

- 修复 V8 运行时中 *Module.name* 的编码。感谢 [@mrmacete][]！


[frida-java-bridge]: https://github.com/frida/frida-java-bridge
[Razvan Sima]: https://twitter.com/0xraaz
[frida-tools]: https://github.com/frida/frida-tools
[@0xraaz]: https://twitter.com/0xraaz
[@mrmacete]: https://twitter.com/bezjaje
