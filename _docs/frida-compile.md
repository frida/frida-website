---
layout: docs
title: frida-compile
permalink: /docs/frida-compile/
---

This is a command-line tool for compiling node-js modules.

CustomModule.js file
{% highlight bash %}
'use strict';
var os = require('os');

const engine = global;

var foo = "test";

engine.foo = foo;

function printExtra(value) {
  console.log(value);
}
engine.printExtra = printExtra;

function getOsInfo() {
  console.log("Platform: " + os.platform());
  console.log("Architecture: " + os.arch());
}
engine.os=getOsInfo;

{% endhighlight %}

Compile script & load it with frida
<div class="note info">
  <h5>Compiling without babel</h5>
  <p>We are using -x option to skip babel transforms.</p>
</div>
{% highlight bash %}
$ frida-compile CustomModule.js -x -o compiled.js

$ frida -l compiled.js 20655
     ____
    / _  |   Frida 11.0.12 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Local::PID::20655]-> foo
"test"
[Local::PID::20655]-> printExtra("someValue")
someValue
undefined
[Local::PID::20655]-> os()
Platform: browser
Architecture: javascript
undefined
[Local::PID::20655]->


{% endhighlight %}
<div class="note">
  <h5>Module development</h5>
<p>For active module development you can use -w option, it will watch for changes and recompile at runtime.</p>
</div>
{% highlight bash %}
$ frida-compile CustomModule.js -x -o compiled.js -w
Compiled 2 files (43 ms)
Compiled 1 file (29 ms)
Compiled 1 file (30 ms)
{% endhighlight %}

<div class="note warning">
  <h5>Compressing</h5>
  <p>To use -c option you need UglifyJS2 module</p>
</div>
