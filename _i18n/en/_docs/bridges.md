Starting from Frida 17.0.0 bridges are no longer bundled together with Frida's GumJS runtime which you can read inside of release [notes][] meaning that the users now will have to specify the bridges they want to use. Frida REPL and `frida-trace` include all three bridges inside of them, so you don't have to deal with it.

## Table of contents

1. **REPL and frida-trace**
    1. [Using plain JavaScript](#using-plain-javascript)
    1. [REPL and frida-trace do compilation automatically](#repl-and-frida-trace-do-compilation-automatically)
    1. [Manually compiling using frida-compile](#manually-compiling-using-frida-compile)
1. **Using API**
    1. [Python example](#python-example)
    1. [Go example](#go-example)

## REPL and frida-trace

We will use the simple script to print `ObjC.available` on the screen.

{% highlight javascript %}
// script.js
console.log(ObjC.available);
{% endhighlight %}

### Using plain JavaScript
This works exactly like before since REPL and frida-trace are bundled with all three bridges.

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

### REPL and frida-trace do compilation automatically

REPL and `frida-trace` can also work with `.ts` files, although you need to first run `npm init` and add `"type":"module"` inside `package.json` file.

### Manually compiling using frida-compile
You need to specify which bridges you want to use (ObjC, Java, Swift) by adding lines inside your script:

* `import ObjC from "frida-objc-bridge"` - for ObjC
* `import Java from "frida-java-bridge"` - for Java
* `import Swift from "frida-swift-bridge"` - for Swift

We will recreate the example above where we used plain JavaScript to print `ObjC.available`.

{% highlight typescript %}
// script.ts
import ObjC from "frida-objc-bridge";

console.log(ObjC.available);
{% endhighlight %}

Initialize and install necessary packages:

{% highlight bash %}
$ npm install frida-objc-bridge 
$ npm install --save-dev @types/frida-gum frida-compile @types/node@~20.9
{% endhighlight %}

Add `"type":"module"` to `package.json` and run `node_modules/.bin/frida-compile -S -c script.ts -o _agent.js`.

{% highlight bash %}
$ node_modules/.bin/frida-compile -S -c script.ts -o _agent.js
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
There are fewer steps to do it using API provided by bindings and they are:
* Write the script
* Run `npm init`
* Install bridge(s) you want, e.g. `frida-objc-bridge`
* Write the code to compile the script and load it to the process

### Python example

{% highlight python %}
import frida

def on_diag(diag):
    print("diag", diag)

def on_message(message, data):
    print(message)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diag)
# script is located in /tmp, so we set project root to /tmp
bundle = compiler.build("script.ts", "/tmp")

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

[notes]: /news/2025/05/17/frida-17-0-0-released/
