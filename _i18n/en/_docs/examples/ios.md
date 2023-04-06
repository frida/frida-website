## Recipes

1. Inject script into process on host via REPL
-
    Injecting a Frida instrumentation script on the host machine can be achieved
    through the following command. Here the **-n** switch specifies the process
    name to attach to.

    `$ frida -n Twitter -l demo1.js`

2. List all running process names and PIDs
-
    The following command lists all the running processes in a tabular format
    with name and PID columns.

    `$ frida-ps`

3. List all running process names on a USB device
-
    The following command lists all the running processes on a **USB device** in
    a tabular format with name and PID columns. The **-U** specifies that a USB
    device is being queried.

    `$ frida-ps -Uai`

4. List all attached devices
-
    The following command lists all the attached devices. Processes on these
    devices can be instrumented by Frida.

    `$ frida-ls-devices`

5. Tracing native APIs
-
    The following command can be used to trace a native API in a specific
    process. Function names can be specified using wildcard characters
    *(as shown below)*, which can be particularly useful while exploring or
    discovering user-defined functions within the process.

    >1. `$ frida-trace -n Twitter -i "*URL*"$`
    >2. `$ frida-trace -U Twitter -i "*URL*"$` *// USB Device*

6. Tracing Objective-C APIs
-
    The following command can be used to trace an Objective-C API in a specific
    process. Notice the difference in switch, in this case it's **-m** instead
    of **-i**. Objective-C APIs names, the Class names as well as the method
    types (class method or instance method) can all be specified using wildcard
    characters *(as shown below)*. This can be particularly useful while
    exploring or discovering user-defined methods within a process.

    `$ frida-trace -U Twitter -m "-[NSURL* *HTTP*]"`

7. Backtracing an Objective-C method call
-
    The following command can be used to generate a backtrace for an Objective-C
    method call in a specific process.

    >**Tip:** Add the following code to the **onEnter** event-handler in the
    auto-generated JS of the desired API

    {% highlight js %}
    log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
    {% endhighlight %}

8. Writing data to file
-
    If you want to write some data to a file, you should ```send()``` it from the
    injected script and receive it in your Frida-based application, where you then
    write it to a file.

    > **Tip:** The data that you ```send()``` should be JSON serializable.

    agent.js:

        const data = { foo: 'bar' };
        send(data);

    app.py:

        import frida

        def on_message(message, data):
            print(message['payload'])

9. Calling a native function
-

{% highlight js %}
const address = Module.getExportByName('libsqlite3.dylib', 'sqlite3_sql');
const sql = new NativeFunction(address, 'char', ['pointer']);
sql(statement);
{% endhighlight %}

Explanation [here](https://gist.github.com/dpnishant/c7c6b47ebfd8cd671ecf).

## Data Structures

>**Tip**: If things don't seem to be working as expected you may be interacting with the wrong data type - run `console.log('Type of args[2] -> ' + new ObjC.Object(args[2]).$className)` to determine the actual type of the object that you're dealing with!

1. Converting NSData to String
-

{% highlight js %}
const data = new ObjC.Object(args[2]);
data.bytes().readUtf8String(data.length());
{% endhighlight %}

>**Tip**: 2nd argument (number of bytes) is not required if the string data is null-terminated.

2. Converting NSData to Binary Data
-

{% highlight js %}
const data = new ObjC.Object(args[2]);
data.bytes().readByteArray(data.length());
{% endhighlight %}

3. Iterating an NSArray
-

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

4. Iterating an NSDictionary
-

{% highlight js %}
const dict = new ObjC.Object(args[2]);
const enumerator = dict.keyEnumerator();
let key;
while ((key = enumerator.nextObject()) !== null) {
  const value = dict.objectForKey_(key);
}
{% endhighlight %}

5. Unarchiving an NSKeyedArchiver
-

{% highlight js %}
const parsedValue = ObjC.classes.NSKeyedUnarchiver.unarchiveObjectWithData_(value);
{% endhighlight %}

6. Reading a struct
-
If args[0] is a pointer to a struct, and let's say you want to read the uint32
at offset 4, you can do it as shown below:

{% highlight js %}
args[0].add(4).readU32();
{% endhighlight %}

## Objective-C examples

### Displaying an alert box on iOS 7

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

### Displaying an alert box on iOS >= 8

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

### Printing an NSURL argument

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
