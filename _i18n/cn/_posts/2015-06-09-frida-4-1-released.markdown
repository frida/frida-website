---
layout: news_item
title: 'Frida 4.1 发布'
date: 2015-06-09 09:00:00 +0100
author: oleavr
version: 4.1
categories: [release]
---

现在是发布时间，这次我们将 iOS 支持提升到一个新的水平，同时也带来了一些可靠的质量改进。我也非常兴奋地宣布，我最近加入了 [NowSecure](https://www.nowsecure.com/)，这个版本的精彩绝非巧合。

让我们从一个全新的 iOS 功能开始。现在可以列出已安装的应用程序，*frida-ps* 可以为您做到这一点：

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

添加 `-i` 开关，它还将包括所有已安装的应用程序，而不仅仅是当前正在运行的应用程序。

这也适用于您选择的语言绑定，例如从 Python：

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

这很酷，但是您不想对这些应用程序进行早期插桩吗？现在您也可以这样做，只需让我们 spawn 一个应用程序标识符：

{% highlight sh %}
$ frida-trace -U -f com.toyopagroup.picaboo -I "libcommonCrypto*"
{% endhighlight %}

或者在 API 级别：

{% highlight python %}
>>> import frida
>>> iphone = frida.get_usb_device()
>>> pid = iphone.spawn(["com.toyopagroup.picaboo"])
>>> snapchat = iphone.attach(pid)
>>> …apply instrumentation…
>>> iphone.resume(pid)
{% endhighlight %}

请注意，为了最大化互操作性，我们在早期启动部分搭载了 *Cydia Substrate*；毕竟如果多个框架都向 *launchd* 注入代码并冒着互相踩踏的风险，那就不太好了。然而，这种依赖关系是软依赖，因此如果在尝试使用应用程序标识符调用 `spawn()` 时未安装 Substrate，我们将抛出异常。

所以，iOS 应用程序的早期检测非常酷。但是，这些应用程序通常消耗大量的 Objective-C API，如果我们想检测它们，我们经常发现自己不得不创建新的 Objective-C 类，以便在应用程序和 API 之间插入委托。如果这样的 Objective-C 类可以用纯 JavaScript 创建，那不是很好吗？现在它们可以了：

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
      implementation(conn, resp) {
      }
    },
    /* Or grab it from an existing class: */
    '- connection:didReceiveResponse:': {
      types: ObjC.classes
          .Foo['- connection:didReceiveResponse:'].types,
      implementation(conn, resp) {
      }
    },
    /* Or from an existing protocol: */
    '- connection:didReceiveResponse:': {
      types: ObjC.protocols.NSURLConnectionDataDelegate
          .methods['- connection:didReceiveResponse:'].types,
      implementation(conn, resp) {
      }
    },
    /* Or write the signature by hand if you really want to: */
    '- connection:didReceiveResponse:': {
      types: 'v32@0:8@16@24',
      implementation(conn, resp) {
      }
    }
  }
});

const proxy = MyConnectionDelegateProxy.alloc().init();
/* use `proxy`, and later: */
proxy.release();
{% endhighlight %}

虽然大多数时候您想构建一个代理对象，在该对象中您传递所有内容，并且只为您真正关心的少数方法做一些日志记录。看看这个：

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
    forward(name) {
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

这就是 Objective-C。感谢 [@marc1006](https://github.com/marc1006)，Dalvik 集成也获得了一些用于枚举已加载类的甜蜜新 API，他还修复了我们对静态方法的处理，并且能够从重写的实现中返回布尔值。

我们还从 [@Tyilo](https://github.com/Tyilo) 那里得到了很多很棒的改进，他帮助改进了 ObjC 集成，将 REPL 打磨成更好的形状，添加了用于枚举 malloc 范围的 API，并向 *NativePointer* 添加了一些便捷 API。

在所有这些进行的同时，[@s1341](https://github.com/s1341) 一直在努力做着惊人的工作，将 Frida 移植到 QNX，现在它真的像魅力一样工作。

让我们浏览一下剩余的更改：

4.0.1:

- objc: 支持更多类型
- frida-trace: 修复 ObjC 跟踪回归

4.0.2:

- frida-node: 修复 *pixels* 属性的编码

4.0.3:

- frida-repl: 修复 Windows 回归

4.0.5:

- objc: 支持更多类型和更好的类型检查
- objc: arm64 现在正常工作
- frida-repl: 允许创建变量

4.0.6:

- platform: 支持向 *send()* 传递纯数据数组
- arm: 支持重定位 *cbz*/*cbnz* 指令

4.1.0:

- platform: 修复写入 stdout 的子进程的生成
- platform: 修复 NativeCallback 对 *bool*/*int8*/*uint8* 返回值的处理（这阻止了 Dalvik 方法重写能够返回 *false*）。
- platform: 允许长度 < 1 的 *Memory.readByteArray()*
- arm: 支持重定位 *ldrpc t2* 指令
- arm: 改进的重定向解析器
- arm64: 修复 *adrp* 指令的重定位
- arm64: 支持重定位 PC 相对 *ldr* 指令
- dalvik: 添加 *Dalvik.enumerateLoadedClasses()*
- dalvik: 修复静态方法的处理
- python: 修复 Windows 上的 *console.log()*
- frida-repl: 错误修复和改进
- frida-trace: 对跟踪 ObjC 方法的 glob 支持

4.1.1:

- platform: 在 *enumerate_applications()* 中添加缺少的 pid 字段

4.1.2:

- objc: 类和代理创建 API
- objc: 用于枚举协议的新 *ObjC.protocols* API

4.1.3:

- platform: 通过在调用 NativeFunction 时释放 V8 锁来改进并发性
- platform: 添加 *Process.getModuleByName(name)*
- platform: 更快更健壮的分离
- python: CLI 工具的稳定性改进
- frida-repl: 用 *prompt-toolkit* 替换 *readline*

4.1.4:

- platform: 更快更健壮的拆卸
- frida-server: 在 *SIGINT* 和 *SIGTERM* 上清理

4.1.5:

- frida-ps: 添加对列出应用程序的支持

4.1.6:

- platform: 修复 Mac、iOS 和 Linux 上生成时的崩溃
- platform: 添加 *NativePointer.compare()* 和 *NativePointer.equals()*
- platform: 添加 *Process.enumerateMallocRanges{,Sync}()*
- frida-trace: 从 Enter 切换到 Ctrl+C 停止
- frida-trace: 修复 iOS 应用程序的生成
- frida-repl: 向自动完成添加原型名称

4.1.7:

- python: CLI 工具稳定性改进

目前就这些。请通过在网络上传播这篇文章来帮助宣传。作为一个开源项目，我们还很小，所以口碑营销对我们来说意义重大。

享受吧！
