Frida CLI is a REPL interface that aims to emulate a lot of the nice
features of IPython (or Cycript), which tries to get you closer to
your code for rapid prototyping and easy debugging.

{% highlight bash %}
# Connect Frida to an iPad over USB and start debugging Safari
$ frida -U Safari

[USB::iPad 4::Safari]->
{% endhighlight %}

## An example session

{% highlight bash %}
# Connect Frida to a locally-running Calculator.app
$ frida Calculator

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

# The code in calc.js has now been loaded and executed. Any changes will be reloaded automatically
[Local::ProcName::Calculator]->

# Manually reload it from file at any time
[Local::ProcName::Calculator]-> %reload
[Local::ProcName::Calculator]->
{% endhighlight %}

## Enable the Node.js compatible debugger

{% highlight bash %}
# Connect Frida to a locally-running Calculator.app
# and load calc.js with the debugger enabled
$ frida Calculator -l calc.js --debug

Debugger listening on port 5858
# We can now run node-inspector and start debugging calc.js
[Local::ProcName::Calculator]->
{% endhighlight %}
