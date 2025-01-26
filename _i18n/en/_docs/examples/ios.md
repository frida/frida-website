Frida provides wrapping functions for Objective-C selectors by replacing the `:` with `_`:

{% highlight js %}
// +[NSJSONSerialization dataWithJSONObject:options:error:]
ObjC.classes.NSJSONSerialization.dataWithJSONObject_options_error_(...)

// NSString *helloWorldString = @"Hello, World!";
var helloWorldString = ObjC.classes.NSString.stringWithString_("Hello, World!");

// [helloWorldString characterAtIndex:0]
helloWorldString.characterAtIndex_(0)
{% endhighlight %}

>**Tip**: If things don't seem to be working as expected you may be interacting with the wrong data type - run the following command to determine the actual type of the object that you're dealing with!

{% highlight js %}
console.log('Type of args[2] -> ' + new ObjC.Object(args[2]).$className)
{% endhighlight %}

## Converting NSData to String

{% highlight js %}
const data = new ObjC.Object(args[2]);
data.bytes().readUtf8String(data.length());
{% endhighlight %}

  >**Tip**: 2nd argument (number of bytes) is not required if the string data is null-terminated.

## Converting NSData to Binary Data

{% highlight js %}
const data = new ObjC.Object(args[2]);
data.bytes().readByteArray(data.length());
{% endhighlight %}

## Iterating an NSArray

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

## Iterating an NSDictionary

{% highlight js %}
const dict = new ObjC.Object(args[2]);
const enumerator = dict.keyEnumerator();
let key;
while ((key = enumerator.nextObject()) !== null) {
  const value = dict.objectForKey_(key);
}
{% endhighlight %}

## Unarchiving an NSKeyedArchiver

{% highlight js %}
const parsedValue = ObjC.classes.NSKeyedUnarchiver.unarchiveObjectWithData_(value);
{% endhighlight %}

## Reading a struct

If args[0] is a pointer to a struct, and let's say you want to read the uint32
at offset 4, you can do it as shown below:
{% highlight js %}
args[0].add(4).readU32();
{% endhighlight %}

## Displaying an alert box on iOS 7

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

## Displaying an alert box on iOS >= 8

This is an implementation of the following
[code](https://developer.apple.com/library/ios/documentation/UIKit/Reference/UIAlertController_class/).

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

## Printing an NSURL argument

The following code shows how you can intercept a call to [UIApplication openURL:] and display the NSURL that is passed.

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
