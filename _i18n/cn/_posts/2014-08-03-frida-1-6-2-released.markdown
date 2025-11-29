---
layout: news_item
title: 'Frida 1.6.2 发布'
date: 2014-08-03 17:00:00 +0100
author: oleavr
version: 1.6.2
categories: [release]
---

现在是发布时间，这次我们为您带来的不仅仅是错误修复。认识一下 `Instruction.parse()`：

{% highlight js %}
const a = Instruction.parse(ptr('0x1234'));
const b = Instruction.parse(a.next);
console.log(a);
console.log(b);
{% endhighlight %}

输出：
{% highlight nasm %}
push rbp
mov rbp, rsp
{% endhighlight %}

您问这是如何实现的？那是很酷的部分。Frida 已经在幕后使用了惊人的 [Capstone disassembly framework](https://www.capstone-engine.org/)，因此将其提供给 JavaScript 运行时非常有意义。查看 [JavaScript API Reference](/docs/javascript-api/) 了解所有详细信息。

享受吧！
