---
layout: docs
title: Gadget
permalink: /docs/gadget/
---

Frida's Gadget is a shared library meant to be loaded by programs to be
instrumented when the [Injected][] mode of operation isn't suitable.

This may be done in a variety of ways, for example:

-   Modifying the source code of the program
-   Patching it or one of its libraries, e.g. by using a tool like
    [insert_dylib][]
-   Using a dynamic linker feature like *LD_PRELOAD* or *DYLD_INSERT_LIBRARIES*

Gadget gets kickstarted as soon as the dynamic linker executes its constructor
function.

It supports three different interactions depending on your use-case, where the
[Listen](#listen) interaction is the default. You can override this by adding a
configuration file. The file should be named exactly like the Gadget binary but
with *.config* as its file extension. So for example if you named the binary
*FridaGadget.dylib* you would name the config file *FridaGadget.config*.

Note that you can name the Gadget binary whatever you want, which is useful for
dodging anti-Frida detection schemes that look for a loaded library with "Frida"
in its name.

The config file should be a UTF-8 encoded text file with a JSON object as its
root. It supports three different keys at the root level:

-   `interaction`: object describing which interaction to use. It defaults to
    the [Listen](#listen) interaction.

-   `teardown`: string specifying either `minimal` or `full`, stating how much
    cleanup to perform when the library gets unloaded. The default is `minimal`,
    which means we don't shut down internal threads and free allocated memory
    and OS resources. This is fine if Gadget's lifetime is linked to the program
    itself. Specify `full` if you intend to unload it at some point.

-   `runtime`: string specifying either `interpreter` or `jit`, essentially
    letting you choose between Duktape and V8, respectively. The default is
    `interpreter`, i.e. Duktape, which uses less memory at the expense of speed
    and JavaScript language features.

## Supported interaction types

  1. [Listen](#listen)
  1. [Script](#script)
  1. [ScriptDirectory](#script-directory)

## Listen

This is the default interaction, where Gadget exposes the same interface as
*frida-server* does, listening on *localhost:27042* by default. The only
difference is that the lists of running processes and installed apps only
contain a single entry, which is for the program itself. The process name is
always just *Gadget*, and the installed app's identifier is always
*re.frida.Gadget*.

In order to achieve early instrumentation we let Gadget's constructor function
block until you either *attach()* to the process, or call *resume()* after going
through the usual *spawn()* -> *attach()* -> *…apply instrumentation…* steps.
This means that existing CLI tools like [frida-trace](/docs/frida-trace/) work
the same ways you're already using them.

If you don't want this blocking behavior and want to let the program boot right
up, or you'd prefer it listening on a different interface or port, you can
customize this through the configuration file.

The default configuration is:

{% highlight json %}
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_load": "wait"
  }
}
{% endhighlight %}

Supported configuration keys are:

-   `address`: string specifying the interface to listen on. Supports both IPv4
    and IPv6. Defaults to `127.0.0.1`. Specify `0.0.0.0` to listen on all IPv4
    interfaces.

-   `port`: number specifying the TCP port to listen on. Defaults to `27042`.

-   `on_load`: string specifying either `resume` or `wait`, stating what to do
    when Gadget is loaded. The default is `wait`, which means it will wait for
    you to connect to it and tell it to resume. Specify `resume` if you would
    like the program to be allowed to start immediately, which is useful if you
    just want to be able to attach at a later time.

## Script

Sometimes it is useful to apply some instrumentation in a fully autonomous
manner, by just loading a script from the filesystem before the program's
entrypoint is executed.

Here's the minimal configuration needed:

{% highlight json %}
{
  "interaction": {
    "type": "script",
    "path": "/home/oleavr/explore.js"
  }
}
{% endhighlight %}

Where *explore.js* contains the following skeleton:

{% highlight js %}
'use strict';

rpc.exports = {
  init: function (stage, parameters) {
    console.log('[init]', stage, JSON.stringify(parameters));

    Interceptor.attach(Module.findExportByName(null, 'open'), {
      onEnter: function (args) {
        var path = Memory.readUtf8String(args[0]);
        console.log('open("' + path + '")');
      }
    });
  },
  dispose: function () {
    console.log('[dispose]');
  }
};
{% endhighlight %}

The [rpc.exports][] part is actually optional, and is useful when your script
needs to be aware of its lifecycle.

Gadget calls your `init()` method and waits for it to return before letting the
program execute its entrypoint. This means you can return a *Promise* if you
need to do something asynchronous, e.g. *Socket.connect()*, and guarantees that
you won't miss any early calls.
The first argument, `stage`, is a string specifying either `early` or `late`,
useful for knowing if Gadget was just loaded, or the script is being reloaded.
More on the latter topic below.
The second argument, `parameters`, is the object optionally specified in the
configuration file, or an empty object if not. This is useful for parameterising
your scripts.

You may also expose a `dispose()` method if you need to perform some explicit
cleanup when the script is unloaded. This typically happens because the process
exits, the Gadget is unloaded, or your script get unloaded before a new version
is loaded from disk.

For debugging you can use *console.log()*, *console.warn()*, and
*console.error()*, which will print to *stdout*/*stderr*.

Supported configuration keys are:

-   `path`: string specifying the filesystem path to the script to load. May
    also be a path relative to where the Gadget binary resides. This key does
    not have a default value and must be provided.

-   `parameters`: object containing arbitrary configuration data that you would
    like to pass to the `init()` RPC method. Defaults to an empty object.

-   `on_change`: string specifying either `ignore` or `reload`, where `ignore`
    means the script will be loaded exactly once, and `reload` means Gadget will
    monitor the file and reload the script anytime it changes. The default is
    `ignore`, but `reload` is highly recommended during development.

## ScriptDirectory

In some cases you may want to tamper with system-wide programs and libraries,
but instead of identifying the program from your script's logic, you might want
to do some minimal filtering and load different scripts based on the program
that Gadget is running inside. You may not even need any filtering, but find it
convenient to treat each script as a separate plugin. On a GNU/Linux system such
scripts could even be provided by packages, making it easy to install tweaks
for existing applications.

Here's the minimal configuration needed:

{% highlight json %}
{
  "interaction": {
    "type": "script-directory",
    "path": "/usr/local/frida/scripts"
  }
}
{% endhighlight %}

Supported configuration keys are:

-   `path`: string specifying the filesystem path to the directory containing
    scripts to load. May also be a path relative to where the Gadget binary
    resides. This key does not have a default value and must be provided.
    Scripts should use *.js* as their file extension, and each script may also
    have configuration data in a *.config* file next to it. This means that
    *twitter.js* may specify its configuration in a file named *twitter.config*.

-   `on_change`: string specifying either `ignore` or `rescan`, where `ignore`
    means the directory will be scanned exactly once, and `rescan` means Gadget
    will monitor the directory and rescan it anytime it changes. The default is
    `ignore`, but `rescan` is highly recommended during development.

Each script's optional configuration file may contain the following keys:

-   `filter`: object containing criteria for this script to be loaded. Only one
    of them has to match, so complex filtering should be implemented in the
    script itself if needed. Supports the following keys specifying what to
    match:

    -   `executables`: array of strings specifying executable names
    -   `bundles`: array of strings specifying bundle identifiers
    -   `objc_classes`: array of strings specifying Objective-C class names

-   `parameters`: object containing arbitrary configuration data that you would
    like to pass to the `init()` RPC method. Defaults to an empty object.

-   `on_change`: string specifying either `ignore` or `reload`, where `ignore`
    means the script will be loaded exactly once, and `reload` means Gadget will
    monitor the file and reload the script anytime it changes. The default is
    `ignore`, but `reload` is highly recommended during development.

Say you want to write a tweak for Twitter's macOS app, you could create
a file named *twitter.js* in */usr/local/frida/scripts*, containing:

{% highlight js %}
'use strict';

var TMTheme = ObjC.classes.TMTheme;

rpc.exports = {
  init: function (stage, parameters) {
    console.log('[init]', stage, JSON.stringify(parameters));

    ObjC.schedule(ObjC.mainQueue, function () {
      TMTheme.switchToTheme_(TMTheme.darkTheme());
    });
  },
  dispose: function () {
    console.log('[dispose]');

    ObjC.schedule(ObjC.mainQueue, function () {
      TMTheme.switchToTheme_(TMTheme.lightTheme());
    });
  }
};
{% endhighlight %}

Then, to make sure this script is only loaded into that specific app, you
would create another file named *twitter.config*, containing:

{% highlight json %}
{
  "filter": {
    "executables": ["Twitter"],
    "bundles": ["com.twitter.twitter-mac"],
    "objc_classes": ["Twitter"]
  }
}
{% endhighlight %}

This example is saying that we would like the script to be loaded if either:

- The executable name is `Twitter`, or
- its bundle identifier is `com.twitter.twitter-mac`, or
- it's got an Objective-C class loaded whose name is `Twitter`.

For this particular example you would probably only filter on the bundle ID,
as that's the most stable identifier, and if needed, do compatibility checks in
code.

Next to the `filter` key you may also specify `parameters` and `on_change`,
just like in the [Script](#script) configuration above.


[Injected]: /docs/modes/#injected
[insert_dylib]: https://github.com/Tyilo/insert_dylib
[rpc.exports]: /docs/javascript-api/#rpc
