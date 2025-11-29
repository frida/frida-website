---
layout: news_item
title: 'Frida 1.0.9 发布'
date: 2014-01-25 23:00:00 +0100
author: oleavr
version: 1.0.9
categories: [release]
---

另一个版本 —— 这次有一些新功能：

- Mac 和 iOS 的 Objective-C 集成。这是一个例子来吊起你的胃口：

{% highlight js %}
const UIAlertView = ObjC.use('UIAlertView'); /* iOS */
ObjC.schedule(ObjC.mainQueue, () => {
    const view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
        "Frida",
        "Hello from Frida",
        ptr("0"),
        "OK",
        ptr("0"));
    view.show();
    view.release();
});
{% endhighlight %}

- `Module.enumerateExports()` 现在也枚举导出的变量，而不仅仅是函数。`onMatch` 回调接收一个 `exp` 对象，其中 `type` 字段是 `function` 或 `variable`。

要获得有关 ObjC 集成的完整信息，请查看 [JavaScript API reference](/docs/javascript-api/)。
