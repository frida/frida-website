---
layout: docs
title: Frida CLI
prev_section: android
next_section: frida-ps
permalink: /docs/frida-cli/
---

Frida CLI is a REPL interface that aims to emulate a lot of the nice
features of IPython (or Cycript), which tries to get you closer to
your code for rapid prototyping and easy debugging.

{% highlight bash %}
# Connect Frida to an iPad over USB and start debugging Safari
$ frida -U Safari
    _____
   (_____)
    |   |    Frida 4.0.0 - A world-class dynamic
    |   |                  instrumentation framework
    |`-'|
    |   |    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'

[USB::iPad 4::Safari]->
{% endhighlight %}

## An example session

{% highlight bash %}
# Connect Frida to a locally-running Calculator.app
$ frida Calculator
    _____
   (_____)
    |   |    Frida 4.0.0 - A world-class dynamic
    |   |                  instrumentation framework
    |`-'|
    |   |    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'

# Look at the local variables/context
[Local::ProcName::Calculator]-> <TAB>
Backtracer           Process
CpuContext           Proxy
Dalvik               Socket
DebugSymbol          Stalker
File                 Thread
Frida                WeakRef
Instruction          clearInterval
Interceptor          clearTimeout
Memory               console
MemoryAccessMonitor  gc
Module               ptr
NULL                 recv
NativeCallback       send
NativeFunction       setInterval
NativePointer        setTimeout
ObjC
# Look at things exposed through the ObjC interface
[Local::ProcName::Calculator]-> ObjC.<TAB>
Object            implement         selector
available         mainQueue         selectorAsString
classes           schedule
# List the first 10 classes (there are a lot of them!)
[Local::...::Calculator]-> Object.keys(ObjC.classes).slice(0, 10)
[
    "NSDrawer",
    "GEOPDETAFilter",
    "NSDeserializer",
    "CBMutableCharacteristic",
    "NSOrthographyCheckingResult",
    "DDVariable",
    "GEOVoltaireLocationShiftProvider",
    "LSDocumentProxy",
    "NSPreferencesModule",
    "CIQRCodeGenerator"
]
{% endhighlight %}

## Loading a script

{% highlight bash %}
# Connect Frida to a locally-running Calculator.app and load calc.js
$ frida Calculator -l calc.js
    _____
   (_____)
    |   |    Frida 4.0.0 - A world-class dynamic
    |   |                  instrumentation framework
    |`-'|
    |   |    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'

# The code in calc.js has now been loaded and executed
[Local::ProcName::Calculator]->
# Reload it from file at any time
[Local::ProcName::Calculator]-> %reload
[Local::ProcName::Calculator]->
{% endhighlight %}

## Enable the Node.js compatible debugger

{% highlight bash %}
# Connect Frida to a locally-running Calculator.app
# and load calc.js with the debugger enabled
$ frida Calculator -l calc.js --debug
    _____
   (_____)
    |   |    Frida 4.0.0 - A world-class dynamic
    |   |                  instrumentation framework
    |`-'|
    |   |    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'

Debugger listening on port 5858
# We can now run node-inspector and start debugging calc.js
[Local::ProcName::Calculator]->
{% endhighlight %}
