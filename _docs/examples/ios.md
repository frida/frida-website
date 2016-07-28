---
layout: docs
title: iOS
permalink: /docs/examples/ios/
---
##Displaying alert box under iOS 7
{% highlight js %}
var UIAlertView = ObjC.classes.UIAlertView; /* iOS 7 */
var view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
    "Frida",
    "Hello from Frida",
    NULL,
    "OK",
    NULL);
view.show();
view.release();
{% endhighlight %}

##Displaying alert box under iOS >= 8
This is an implementation of the following [code](https://developer.apple.com/library/ios/documentation/UIKit/Reference/UIAlertController_class/)
{% highlight js %}
/* defining a Block that will be passed as handler parameter to +[UIAlertAction actionWithTitle:style:handler:] */
var handler = new ObjC.Block({ retType: 'void', argTypes: ['object'], implementation: function () {}})

/* mapping of ObjC classes */
var UIAlertController = ObjC.classes.UIAlertController;
var UIAlertAction = ObjC.classes.UIAlertAction;
var UIApplication = ObjC.classes.UIApplication;	

/* using Grand Central Dispatch to pass messages (invoke methods) in application's main thread */
ObjC.schedule(ObjC.mainQueue, function () {
  /* using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle*/ 
  var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_("Frida","Hello from Frida", 1);
  /* again using integer numeral for style parameter that is enum*/
  var defaultAction = UIAlertAction.actionWithTitle_style_handler_("OK",0,handler);
  alert.addAction_(defaultAction);
  /* instead of using ObjC.choose and looking for UIViewController on the heap, we have a direct access with UIApplication */
  UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
})
{% endhighlight %}

_Please click "Improve this page" above and add an example. Thanks!_
