---
layout: docs
title: iOS
permalink: /docs/examples/ios/
---

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

    ```log('\tBacktrace:\n\t' + Thread.backtrace(this.context,
Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
.join('\n\t'));```

8. Writing data to file
-
    If you want to write some data to a file, you should ```send()``` it from the
    injected script and receive it in your Frida-based application, where you then
    write it to a file.

    > **Tip:** The data that you ```send()``` should be JSON serializable.

    agent.js:

        var data = { foo: 'bar' };
        send(data);

    app.py:

        import frida

        def on_message(message, data):
            print(message['payload'])

9. Calling a native function
-
```
var address = Module.findExportByName('libsqlite3.dylib', 'sqlite3_sql');
var sql = new NativeFunction(address, 'char', ['pointer']);
sql(statement);
```

Explanation [here](https://gist.github.com/dpnishant/c7c6b47ebfd8cd671ecf).

## Data Structures

1. Converting NSData to String
-
```
var data = new ObjC.Object(args[2]);
Memory.readUtf8String(data.bytes(), data.length());
```
>**Tip**: 2nd argument (number of bytes) is not required if the string data is null-terminated.

2. Converting NSData to Binary Data
-
```
Memory.readByteArray(data.bytes(), data.length());
```

3. Iterating an NSArray
-
```
var count = array.count();
for (var i = 0; i !== count; i++) {
  var element = array.objectAtIndex_(i);
}
```

4. Iterating an NSDictionary
-
```
var enumerator = dict.keyEnumerator();
var key;
while ((key = enumerator.nextObject()) !== null) {
  var value = dict.objectForKey_(key);
}
```

5. Unarchiving an NSKeyedArchiver
-
```
var parsedValue = ObjC.classes.NSKeyedUnarchiver.unarchiveObjectWithData_(value);
```

6. Reading a struct
-
If args[0] is a pointer to a struct, and let's say you want to read the uint32
at offset 4, you can do it as shown below:
```
Memory.readU32(args[0].add(4));
```

## Objective-C examples

### Displaying an alert box on iOS 7

{% highlight js %}
var UIAlertView = ObjC.classes.UIAlertView; /* iOS 7 */
var view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
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
var handler = new ObjC.Block({
  retType: 'void',
  argTypes: ['object'],
  implementation: function () {
  }
});

// Import ObjC classes
var UIAlertController = ObjC.classes.UIAlertController;
var UIAlertAction = ObjC.classes.UIAlertAction;
var UIApplication = ObjC.classes.UIApplication;

// Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
ObjC.schedule(ObjC.mainQueue, function () {
  // Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
  var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_('Frida', 'Hello from Frida', 1);
  // Again using integer numeral for style parameter that is enum
  var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
  alert.addAction_(defaultAction);
  // Instead of using `ObjC.choose()` and looking for UIViewController instances
  // on the heap, we have direct access through UIApplication:
  UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
})
{% endhighlight %}


### Printing an NSURL argument

The following code shows how you can intercept a call to [UIApplication openURL:] and display the NSURL that is passed.

{% highlight js %}
// Get a reference to the openURL selector
var openURL = ObjC.classes.UIApplication["- openURL:"];

// Intercept the method
Interceptor.attach(openURL.implementation, {
  onEnter: function(args) {
    // As this is an ObjectiveC method, the arguments are as follows:
    // 1. 'self'
    // 2. The selector (openURL:)
    // 3. The first argument to the openURL selector
    var myNSURL = new ObjC.Object(args[2]);
    // Convert it to a JS string
    var myJSURL = myNSURL.absoluteString().toString();
    // Log it
    console.log("Launching URL: " + str);
  }
});
{% endhighlight %}