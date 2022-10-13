---
layout: news_item
title: 'Frida 15.2.0 Released'
date: 2022-07-21 00:02:32 +0200
author: oleavr
version: 15.2.0
categories: [release]
---

Super-excited about this one. What I've been wanting to do for years is to
streamline Frida's JavaScript developer experience. As a developer I may start
out with a really simple agent, but as it grows I start to feel the pain.

Early on I may want to split up the agent into multiple files. I may also want
to use some off-the-shelf packages from npm, such as [frida-remote-stream][].
Later I'd want code completion, inline docs, type checking, etc., so I move the
agent to TypeScript and fire up VS Code.

Since we've been piggybacking on the amazing frontend web tooling that's already
out there, we already have all the pieces of the puzzle. We can use a bundler
such as [Rollup][] to combine our source files into a single .js, we can use
[@frida/rollup-plugin-node-polyfills][] for interop with packages from npm, and
we can plug in [@rollup/plugin-typescript][] for TypeScript support.

That is quite a bit of plumbing to set up over and over though, so I eventually
created [frida-compile][] as a simple tool that does the plumbing for you, with
configuration defaults optimized for what makes sense in a Frida context. Still
though, this does require some boilerplate such as package.json, tsconfig.json,
and so forth.

To solve that, I published [frida-agent-example][], a repo that can be cloned
and used as a starting point. That is still a bit of friction, so later
frida-tools got a new CLI tool called frida-create. Anyway, even with all of
that, we're still asking the user to install Node.js and deal with npm, and
potentially also feel confused by the .json files just sitting there.

Then it struck me. What if we could use frida-compile to compile frida-compile
into a self-contained .js that we can run on Frida's system session? The system
session is a somewhat obscure feature where you can load scripts inside of the
process hosting frida-core. For example if you're using our Python bindings,
that process would be the Python interpreter.

Once we are able to run that frida-compile agent inside of GumJS, we can
communicate with it and turn that into an API. This API can then be exposed
by language bindings, and frida-tools can consume it to give the user a
frida-compile CLI tool that doesn't require Node.js/npm to be installed. Tools
such as our REPL can seamlessly use this API too if the user asks it to load a
script with a .ts extension.

And all of that is precisely what we have done! 🥳

## build()

Here's how easy it is to use it from Python:

{% highlight python %}
import frida

compiler = frida.Compiler()
bundle = compiler.build("agent.ts")
{% endhighlight %}

The *bundle* variable is a string that can be passed to create_script(), or
written to a file.

Running that example we might see something like:

{% highlight bash %}
Traceback (most recent call last):
  File "/home/oleavr/src/explore.py", line 4, in <module>
    bundle = compiler.build("agent.ts")
  File "/home/oleavr/.local/lib/python3.10/site-packages/frida/core.py", line 76, in wrapper
    return f(*args, **kwargs)
  File "/home/oleavr/.local/lib/python3.10/site-packages/frida/core.py", line 1150, in build
    return self._impl.build(entrypoint, **kwargs)
frida.NotSupportedError: compilation failed
{% endhighlight %}

That makes us wonder *why* it failed, so let's add a handler for the
*diagnostics* signal:

{% highlight python %}
import frida

def on_diagnostics(diag):
    print("on_diagnostics:", diag)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
bundle = compiler.build("agent.ts")
{% endhighlight %}

And suddenly it's all making sense:

{% highlight bash %}
on_diagnostics: [{'category': 'error', 'code': 6053,
    'text': "File '/home/oleavr/src/agent.ts' not "
            "found.\n  The file is in the program "
            "because:\n    Root file specified for"
             " compilation"}]
…
{% endhighlight %}

We forgot to actually create the file! Ok, let's create *agent.ts*:

{% highlight js %}
console.log("Hello from Frida:", Frida.version);
{% endhighlight %}

And let's also write that script to a file:

{% highlight python %}
import frida

def on_diagnostics(diag):
    print("on_diagnostics:", diag)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
bundle = compiler.build("agent.ts")
with open("_agent.js", "w", newline="\n") as f:
    f.write(bundle)
{% endhighlight %}

If we now run it, we should have an _agent.js ready to go:

{% highlight bash %}
$ cat _agent.js
📦
175 /explore.js.map
39 /explore.js
✄
{"version":3,"file":"explore.js","sourceRoot":"/home/oleavr/src/","sources":["explore.ts"],"names":[],"mappings":"AAAA,OAAO,CAAC,GAAG,CAAC,SAAS,KAAK,CAAC,OAAO,GAAG,CAAC,CAAC"}
✄
console.log(`Hello ${Frida.version}!`);
{% endhighlight %}

This weird-looking format is how GumJS' allows us to opt into the new ECMAScript
Module (ESM) format where code is confined to the module it belongs to instead
of being evaluated in the global scope. What this also means is we can load
multiple modules that import/export values. The .map files are optional and can
be omitted, but if left in they allow GumJS to map the generated JavaScript line
numbers back to TypeScript in stack traces.

Anyway, let's take _agent.js for a spin:

{% highlight bash %}
$ frida -p 0 -l _agent.js
     ____
    / _  |   Frida 15.2.0 - A world-class dynamic instrumentation toolkit
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
Hello 15.2.0!
[Local::SystemSession ]->
{% endhighlight %}

It works! Now let's try refactoring it to split the code into two files:

### agent.ts

{% highlight typescript %}
import { log } from "./log.js";

log("Hello from Frida:", Frida.version);
{% endhighlight %}

### log.ts

{% highlight typescript %}
export function log(...args: any[]) {
    console.log(...args);
}
{% endhighlight %}

If we now run our example compiler script again, it should produce a slightly
more interesting-looking _agent.js:

{% highlight bash %}
📦
204 /agent.js.map
72 /agent.js
199 /log.js.map
58 /log.js
✄
{"version":3,"file":"agent.js","sourceRoot":"/home/oleavr/src/","sources":["agent.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,GAAG,EAAE,MAAM,UAAU,CAAC;AAE/B,GAAG,CAAC,mBAAmB,EAAE,KAAK,CAAC,OAAO,CAAC,CAAC"}
✄
import { log } from "./log.js";
log("Hello from Frida:", Frida.version);
✄
{"version":3,"file":"log.js","sourceRoot":"/home/oleavr/src/","sources":["log.ts"],"names":[],"mappings":"AAAA,MAAM,UAAU,GAAG,CAAC,GAAG,IAAW;IAC9B,OAAO,CAAC,GAAG,CAAC,GAAG,IAAI,CAAC,CAAC;AACzB,CAAC"}
✄
export function log(...args) {
    console.log(...args);
}
{% endhighlight %}

Loading that into the REPL should yield the exact same result as before.

## watch()

Let's turn our toy compiler into a tool that loads the compiled script, and
recompiles whenever a source file changes on disk:

{% highlight python %}
import frida
import sys

session = frida.attach(0)
script = None

def on_output(bundle):
    global script
    if script is not None:
        print("Unloading old bundle...")
        script.unload()
        script = None
    print("Loading bundle...")
    script = session.create_script(bundle)
    script.on("message", on_message)
    script.load()

def on_diagnostics(diag):
    print("on_diagnostics:", diag)

def on_message(message, data):
    print("on_message:", message)

compiler = frida.Compiler()
compiler.on("output", on_output)
compiler.on("diagnostics", on_diagnostics)
compiler.watch("agent.ts")

sys.stdin.read()
{% endhighlight %}

And off we go:

{% highlight bash %}
$ python3 explore.py
Loading bundle...
Hello from Frida: 15.2.0
{% endhighlight %}

If we leave that running and then edit the source code on disk we should see
some new output:

{% highlight bash %}
Unloading old bundle...
Loading bundle...
Hello from Frida version: 15.2.0
{% endhighlight %}

Yay!

## frida-compile

We can also use frida-tools' new frida-compile CLI tool:

{% highlight bash %}
$ frida-compile agent.ts -o _agent.js
{% endhighlight %}

It also supports watch mode:

{% highlight bash %}
$ frida-compile agent.ts -o _agent.js -w
{% endhighlight %}

## REPL

Our REPL is also powered by the new frida.Compiler:

{% highlight bash %}
$ frida -p 0 -l agent.ts
     ____
    / _  |   Frida 15.2.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Compiled agent.ts (1428 ms)
Hello from Frida version: 15.2.0
[Local::SystemSession ]->
{% endhighlight %}

## Shoutout

Shoutout to [@hsorbo][] for the fun and productive pair-programming sessions
where we were working on frida.Compiler together! 🙌

## EOF

There are also quite a few other goodies in this release, so definitely check
out the changelog below.

Enjoy!

### Changelog

- core: Add Compiler API. Only exposed by Python bindings for now, but available
  from C/Vala.
- interceptor: Improve *replace()* to support returning original. Thanks
  [@aviramha][]!
- gumjs: Fix typing for *pc* in the writer options.
- gumjs: Fix V8 ESM crash with circular dependencies.
- gumjs: Handle ESM bundles with multiple aliases per module.
- gumjs: Tighten up the *Checksum* data argument parsing.
- android: Fix null pointer deref in crash delivery. Thanks [@muhzii][]!
- fruity: Use env variables to find usbmuxd. Thanks [@0x3c3e][]!
- ios: Make Substrate detection logic a bit more resilient. Thanks
  [@lemon4ex][]!
- meson: Only try to use V8 if available. Thanks [@muhzii][]!
- windows: Add support for building without V8.
- devkit: Fix library dependency hints on Windows. Thanks [@nblog][]!


[frida-remote-stream]: https://github.com/nowsecure/frida-remote-stream
[Rollup]: https://rollupjs.org/guide/en/
[@frida/rollup-plugin-node-polyfills]: https://www.npmjs.com/package/@frida/rollup-plugin-node-polyfills
[@rollup/plugin-typescript]: https://www.npmjs.com/package/@rollup/plugin-typescript
[frida-compile]: https://www.npmjs.com/package/frida-compile
[frida-agent-example]: https://github.com/oleavr/frida-agent-example
[@hsorbo]: https://twitter.com/hsorbo
[@aviramha]: https://github.com/aviramha
[@muhzii]: https://github.com/muhzii
[@0x3c3e]: https://github.com/0x3c3e
[@lemon4ex]: https://github.com/lemon4ex
[@nblog]: https://github.com/nblog
