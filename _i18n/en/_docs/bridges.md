Starting with Frida 17.0.0, bridges are no longer bundled with Frida's GumJS
runtime. You can read more about it in the [release notes][]. This means that
users now have to explicitly pull in the bridges they want to use. The Frida
REPL and `frida-trace` do however come with all three bridges bundled, for
compatibility with existing scripts.

## Table of contents

1. **REPL and frida-trace**
    1. [Using plain JavaScript](#using-plain-javascript)
    1. [REPL automatic compilation](#repl-automatic-compilation)
    1. [Manually compiling using frida-compile](#manually-compiling-using-frida-compile)
1. **Using API**
    1. [Python example](#python-example)
    1. [Go example](#go-example)

## REPL and frida-trace

We will use a simple script to print `ObjC.available` to the screen.

{% highlight javascript %}
// script.js
console.log(ObjC.available);
{% endhighlight %}

### Using plain JavaScript

This works exactly like before since REPL and frida-trace have all three bridges
bundled.

{% highlight bash %}
$ frida -p0 -l script.js
     ____
    / _  |   Frida 17.0.5 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Attaching...
true
[Local::SystemSession ]->
{% endhighlight %}

### REPL automatic compilation

The REPL can also work with `.ts` files: use `frida-create -t agent` in an empty
directory to set up the needed scaffolding.

### Manually compiling using frida-compile

You need to specify which bridges you want to use (ObjC, Java, Swift) by adding
lines inside your script:

* `import ObjC from "frida-objc-bridge";` - for ObjC
* `import Swift from "frida-swift-bridge";` - for Swift
* `import Java from "frida-java-bridge";` - for Java

We will recreate the example above where we used plain JavaScript to print
`ObjC.available`.

{% highlight typescript %}
// script.ts
import ObjC from "frida-objc-bridge";

console.log(ObjC.available);
{% endhighlight %}

Initialize and install necessary packages in an empty directory:

{% highlight bash %}
$ frida-create -t agent
$ npm install
$ npm install frida-objc-bridge
{% endhighlight %}

Then compile the agent and load it:

{% highlight bash %}
$ frida-compile script.ts -o _agent.js -S -c
$ frida -p0 -l _agent.js
     ____
    / _  |   Frida 17.0.5 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Attaching...
true
[Local::SystemSession ]->
{% endhighlight %}

## Using API

There are a few steps needed to do it using APIs provided by bindings, which
are:

* Write the script
* Run `frida-create -t agent`
* Install bridge(s) you want, e.g. `frida-objc-bridge`
* Write the code to compile the script and load it in the process

### Python example

{% highlight python %}
import frida

def on_diagnostics(diag):
    print("diag", diag)

def on_message(message, data):
    print(message)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
# script is located in /tmp, so we set project root to /tmp
bundle = compiler.build("script.ts", project_root="/tmp")

session = frida.attach(0)

script = session.create_script(bundle)

script.on("message", on_message)
script.load()
{% endhighlight %}

### Go example

{% highlight go %}
package main

import (
	"bufio"
	"fmt"
	"github.com/frida/frida-go/frida"
	"os"
)

func main() {
	comp := frida.NewCompiler()
	comp.On("diagnostics", func(diag string) {
		fmt.Printf("Diagnostics: %s\n", diag)
	})

	bopts := frida.NewCompilerOptions()
	bopts.SetProjectRoot("/tmp")
	bopts.SetSourceMaps(frida.SourceMapsOmitted)
	bopts.SetJSCompression(frida.JSCompressionTerser)

	bundle, err := comp.Build("script.ts", bopts)
	if err != nil {
		panic(err)
	}

	session, err := frida.Attach(0)
	if err != nil {
		panic(err)
	}

	script, err := session.CreateScript(bundle)
	if err != nil {
		panic(err)
	}

	script.On("message", func(message string, data []byte) {
		fmt.Printf("%s\n", message)
	})

	script.Load()

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
{% endhighlight %}

[release notes]: /news/2025/05/17/frida-17-0-0-released/
