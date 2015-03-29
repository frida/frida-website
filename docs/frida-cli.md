---
layout: docs
title: Frida CLI
prev_section: android
next_section: frida-ps
permalink: /docs/frida-cli/
---

Frida CLI is a REPL interface that aims to emulate a lot of the nice features of IPython (or Cycript), which tries to get you closer to your code for rapid prototyping and easy debugging.

{% highlight bash %}
# Connect frida to an ipad over USB and start debugging safari
~ $ frida -U Safari
    _____
   (_____)
    |   |    Frida v3.0 - A world-class dynamic instrumentation framework
    |   |
    |`-'|    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'


Attaching...
[USB::iPad 4::Safari]->
{% endhighlight %}

## An example session

{% highlight bash %}
# Connect frida to a locally-running Calculator.app
~ $ frida Calculator
    _____
   (_____)
    |   |    Frida v3.0 - A world-class dynamic instrumentation framework
    |   |
    |`-'|    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'


Attaching...
# Look at the local variables/context
[Local::ProcName::Calculator]-> <TAB>
Dalvik          Memory          NativeFunction  Proxy           WeakRef         gc              resume
File            Module          NativePointer   Socket          clearInterval   modules         send
Instruction     NULL            ObjC            Stalker         clearTimeout    ptr             setInterval
Interceptor     NativeCallback  Process         Thread          console         recv            setTimeout
# Look at things exposed through the ObjC interface
[Local::ProcName::Calculator]-> ObjC.<TAB>
available         classes           mainQueue         schedule          selectorAsString
cast              implement         refreshClasses    selector          use
# List the first 10 classes (there are a lot of them!)
[Local::ProcName::Calculator]-> ObjC.classes.slice(0,10)
[
    "LSApplicationWorkspace",
    "NSNibOutletConnector",
    "IOBluetoothSerialPort",
    "RAWTemperatureAdjust",
    "NSMergedPolicyLocalizationPolicy",
    "NSCountedSet",
    "CKNotification",
    "VoiceSettingsAlertController",
    "CIWhitePoint",
    "NSDecimalNumberHandler"
]
{% endhighlight %}


More derp