本节旨在包含使用 Frida 时经常遇到的最佳实践和陷阱。

### 字符串分配 (UTF-8/UTF-16/ANSI)

阅读文档后，人们可能会认为分配/替换字符串就像这样简单：

{% highlight javascript %}
onEnter(args) {
  args[0].writeUtf8String('mystring');
}
{% endhighlight %}

但是，这可能是不可能的，因为指向的字符串可能：

- 驻留在“只读数据”段中，该段作为只读映射到进程的地址空间；
- 比那里的字符串长，因此 *writeUtf8String()* 会导致缓冲区溢出并可能破坏不相关的内存。

即使您可以通过使用 *Memory.protect()* 解决前一个问题，也有一个更好的解决方案：分配一个新字符串并替换参数。

但是有一个陷阱：*Memory.allocUtf8String()* 返回的值必须保持活动状态——一旦 JavaScript 值被垃圾回收，它就会被释放。这意味着它至少需要在函数调用期间保持活动状态，在某些情况下甚至更长；确切的语义取决于 API 的设计方式。

考虑到这一点，执行此操作的可靠方法是：

{% highlight javascript %}
onEnter(args) {
  const buf = Memory.allocUtf8String('mystring');
  this.buf = buf;
  args[0] = buf;
}
{% endhighlight %}

它的工作原理是 *this* 绑定到一个每个线程和每个调用都存在的对象，您存储在那里的任何东西都将在 *onLeave* 中可用，这甚至在递归的情况下也有效。这样您就可以在 *onEnter* 中读取参数，并在稍后的 *onLeave* 中访问它们。这也是在函数调用期间保持内存分配处于活动状态的推荐方法。

如果函数保留指针并在函数调用完成后也使用它，一种解决方案是像这样操作：

{% highlight javascript %}
const myStringBuf = Memory.allocUtf8String('mystring');

Interceptor.attach(f, {
  onEnter(args) {
    args[0] = myStringBuf;
  }
});
{% endhighlight %}

### 重用参数

在 *onEnter* 回调中读取参数时，通常通过索引访问每个参数。但是当多次访问同一个参数时会发生什么？以这段代码为例：

{% highlight javascript %}
Interceptor.attach(f, {
  onEnter(args) {
    if (!args[0].readUtf8String(4).includes('MZ')) {
      console.log(hexdump(args[0]));
    }
  }
});
{% endhighlight %}

在上面的示例中，第一个参数从 *args* 数组中获取了两次，这就支付了两次向 *frida-gum* 查询此信息的成本。为了避免在多次需要相同参数时浪费宝贵的 CPU 周期，最好使用局部变量存储此信息：

{% highlight javascript %}
Interceptor.attach(f, {
  onEnter(args) {
    const firstArg = args[0];
    if (!firstArg.readUtf8String(4).includes('MZ')) {
      console.log(hexdump(firstArg));
    }
  }
});
{% endhighlight %}
