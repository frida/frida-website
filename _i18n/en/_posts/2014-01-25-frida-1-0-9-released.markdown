---
layout: news_item
title: 'Frida 1.0.9 Released'
date: 2014-01-25 23:00:00 +0100
author: oleavr
version: 1.0.9
categories: [release]
---

Another release — this time with some new features:

- Objective-C integration for Mac and iOS. Here's an example to whet your
  appetite:

{% highlight js %}
var UIAlertView = ObjC.use('UIAlertView'); /* iOS */
ObjC.schedule(ObjC.mainQueue, function () {
    var view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
        "Frida",
        "Hello from Frida",
        ptr("0"),
        "OK",
        ptr("0"));
    view.show();
    view.release();
});
{% endhighlight %}

- `Module.enumerateExports()` now also enumerates exported variables and not
  just functions. The `onMatch` callback receives an `exp` object where the
  `type` field is either `function` or `variable`.

To get the full scoop on the ObjC integration, have a look at the
[JavaScript API reference](https://frida.re/docs/javascript-api/).
