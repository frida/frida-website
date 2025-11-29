Frida 通过将 `:` 替换为 `_` 来提供 Objective-C 选择器的包装函数：

{% highlight js %}
// +[NSJSONSerialization dataWithJSONObject:options:error:]
ObjC.classes.NSJSONSerialization.dataWithJSONObject_options_error_(...)

// NSString *helloWorldString = @"Hello, World!";
var helloWorldString = ObjC.classes.NSString.stringWithString_("Hello, World!");

// [helloWorldString characterAtIndex:0]
helloWorldString.characterAtIndex_(0)
{% endhighlight %}

>**提示**：如果事情似乎没有按预期工作，您可能正在与错误的数据类型交互 - 运行以下命令以确定您正在处理的对象的实际类型！

{% highlight js %}
console.log('Type of args[2] -> ' + new ObjC.Object(args[2]).$className)
{% endhighlight %}

## 将 NSData 转换为 String

{% highlight js %}
const data = new ObjC.Object(args[2]);
data.bytes().readUtf8String(data.length());
{% endhighlight %}

  >**提示**：如果字符串数据以 null 结尾，则不需要第 2 个参数（字节数）。

## 将 NSData 转换为二进制数据

{% highlight js %}
const data = new ObjC.Object(args[2]);
data.bytes().readByteArray(data.length());
{% endhighlight %}

## 迭代 NSArray

{% highlight js %}
const array = new ObjC.Object(args[2]);
/*
 * Be sure to use valueOf() as NSUInteger is a Number in
 * 32-bit processes, and UInt64 in 64-bit processes. This
 * coerces it into a Number in the latter case.
 */
const count = array.count().valueOf();
for (let i = 0; i !== count; i++) {
  const element = array.objectAtIndex_(i);
}
{% endhighlight %}

## 迭代 NSDictionary

{% highlight js %}
const dict = new ObjC.Object(args[2]);
const enumerator = dict.keyEnumerator();
let key;
while ((key = enumerator.nextObject()) !== null) {
  const value = dict.objectForKey_(key);
}
{% endhighlight %}

## 解档 NSKeyedArchiver

{% highlight js %}
const parsedValue = ObjC.classes.NSKeyedUnarchiver.unarchiveObjectWithData_(value);
{% endhighlight %}

## 读取结构体

如果 args[0] 是指向结构体的指针，假设您想读取偏移量 4 处的 uint32，您可以如下所示进行操作：
{% highlight js %}
args[0].add(4).readU32();
{% endhighlight %}

## 在 iOS 7 上显示警报框

{% highlight js %}
const UIAlertView = ObjC.classes.UIAlertView; /* iOS 7 */
const view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
    'Frida',
    'Hello from Frida',
    NULL,
    'OK',
    NULL);
view.show();
view.release();
{% endhighlight %}

## 在 iOS >= 8 上显示警报框

这是以下 [代码](https://developer.apple.com/library/ios/documentation/UIKit/Reference/UIAlertController_class/) 的实现。

{% highlight js %}
// Defining a Block that will be passed as handler parameter to +[UIAlertAction actionWithTitle:style:handler:]
const handler = new ObjC.Block({
  retType: 'void',
  argTypes: ['object'],
  implementation() {
  }
});

// Import ObjC classes
const UIAlertController = ObjC.classes.UIAlertController;
const UIAlertAction = ObjC.classes.UIAlertAction;
const UIApplication = ObjC.classes.UIApplication;

// Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
ObjC.schedule(ObjC.mainQueue, () => {
  // Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
  const alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_('Frida', 'Hello from Frida', 1);
  // Again using integer numeral for style parameter that is enum
  const defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
  alert.addAction_(defaultAction);
  // Instead of using `ObjC.choose()` and looking for UIViewController instances
  // on the heap, we have direct access through UIApplication:
  UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
});
{% endhighlight %}

## 打印 NSURL 参数

以下代码显示了如何拦截对 [UIApplication openURL:] 的调用并显示传递的 NSURL。

{% highlight js %}
// Get a reference to the openURL selector
const openURL = ObjC.classes.UIApplication['- openURL:'];

// Intercept the method
Interceptor.attach(openURL.implementation, {
  onEnter(args) {
    // As this is an Objective-C method, the arguments are as follows:
    // 0. 'self'
    // 1. The selector (openURL:)
    // 2. The first argument to the openURL method
    const myNSURL = new ObjC.Object(args[2]);
    // Convert it to a JS string
    const myJSURL = myNSURL.absoluteString().toString();
    // Log it
    console.log('Launching URL: ' + myJSURL);
  }
});
{% endhighlight %}
