---
layout: news_item
title: 'Frida 11.0 Released'
date: 2018-05-05 23:51:56 +0200
author: oleavr
version: 11.0
categories: [release]
---

It's time to overhaul the *spawn()* API and fix some rough edges in the spawn-
and child-gating APIs.

### spawn()

Say you're using Frida's Python bindings, you'd currently do:

{% highlight python %}
pid = device.spawn(["/bin/cat", "/etc/passwd"])
{% endhighlight %}

Or to spawn an iOS app:

{% highlight python %}
pid = device.spawn(["com.apple.mobilesafari"])
{% endhighlight %}

Well, that's pretty much all you could do with that API really... except one
thing that wasn't exposed by the Python and Node.js bindings. We'll get to
that in a bit. Before we go there, let's take a peek at the underlying [API][]
in frida-core, which these bindings expose to different languages:

{% highlight vala %}
namespace Frida {
	…
	public class Device : GLib.Object {
		…
		public async uint spawn (string path,
			string[] argv, string[] envp)
			throws Frida.Error;
		public uint spawn_sync (string path,
			string[] argv, string[] envp)
			throws Frida.Error;
	}
	…
}
{% endhighlight %}

That's [Vala][] code by the way, which is the language that frida-core is
written in. It's a C#-like language that compiles to C, and it's pretty awesome.
But I digress. The first method, *spawn()* is asynchronous, allowing the calling
thread to do other things while the call is in progress, whereas *spawn_sync()*
blocks until the operation completes.

Those two methods compile down to the following three C functions:

{% highlight c %}
void frida_device_spawn (FridaDevice * self,
    const gchar * path,
    gchar ** argv, int argv_length,
    gchar ** envp, int envp_length,
    GAsyncReadyCallback callback, gpointer user_data);
guint frida_device_spawn_finish (FridaDevice * self,
    GAsyncResult * result, GError ** error);
guint frida_device_spawn_sync (FridaDevice * self,
    const gchar * path,
    gchar ** argv, int argv_length,
    gchar ** envp, int envp_length,
    GError ** error);
{% endhighlight %}

The first two constitute *spawn()*, where you'd call the first giving it a
callback, and once that callback gets called you'd call the second one,
*spawn_finish()*, giving it the *GAsyncResult* your callback was given.
The return value is the PID, or, in case it failed, the *error* out-argument
explains what went wrong. This is the [GIO][] async pattern in case you're
curious.

As for the third, *spawn_sync()*, this is what Frida's Python bindings use.
Our Node.js bindings actually use the first two, as those bindings are fully
asynchronous. Someday it would be nice to also migrate our Python bindings to
be fully async, by integrating with the *async/await* support introduced in
Python 3.5.

Anyway, returning to the examples above, I mentioned there was something not
exposed. If you look closely at the frida-core API you'll notice that there's
the *envp* string-array. Peeking under the hood of the bindings, you'd realize
we did indeed not expose this, and we actually did this:

{% highlight c %}
  envp = g_get_environ ();
  envp_length = g_strv_length (envp);
{% endhighlight %}

So that means we passed along whatever the Python process' environment happened
to be. That's definitely not good if the actual spawning happened on another
system entirely, like on a connected iOS or Android device. What made this
slightly less problematic was the fact that *envp* was ignored when spawning
iOS and Android apps, and only used when spawning regular programs.

Another issue with this old API is that the declaration, *string[] envp*, means
it isn't nullable, which it would have been if the declaration had been:
*string[]? envp*. That means there is no way to distinguish between wanting to
spawn without any environment, which intuitively would mean "use defaults", and
an empty environment.

As I was about to fix this aspect of the API, I realized that it was time to
also fix a few other long-standing issues with it, like being able to:

- provide just a few extra environment variables on top of the defaults
- set the working directory
- customize stdio redirection
- pass along platform-specific options

Up until this point we have always redirected stdio to our own pipes, and
streamed any output through the *output* signal on *Device*. There was also
*Device.input()* for writing to *stdin*. Those APIs are still the same, the
only difference is that we no longer do such redirection by default. Most of
you were probably not too bothered with this, though, as we didn't implement
such redirection for iOS and Android apps. Starting with this release we do
however finally implement it for iOS apps.

By now you're probably wondering what the new API looks like. Let's have a look:

{% highlight vala %}
namespace Frida {
	…
	public class Device : GLib.Object {
		…
		public async uint spawn (string program,
			Frida.SpawnOptions? options = null)
			throws Frida.Error;
		public uint spawn_sync (string program,
			Frida.SpawnOptions? options = null)
			throws Frida.Error;
	}
	…
	public class SpawnOptions : GLib.Object {
		public string[]? argv { get; set; }
		public string[]? envp { get; set; }
		public string[]? env { get; set; }
		public string? cwd { get; set; }
		public Frida.Stdio stdio { get; set; }
		public GLib.VariantDict aux { get; }

		public SpawnOptions ();
	}
	…
}
{% endhighlight %}

So going back to the Python examples at the beginning, those still work without
any changes. But, instead of:

{% highlight python %}
device.spawn(["com.apple.mobilesafari"])
{% endhighlight %}

You can now also do:

{% highlight python %}
device.spawn("com.apple.mobilesafari")
{% endhighlight %}

As the first argument is the *program* to spawn. You can still pass an *argv*
here and that will be used to set the *argv* option, meaning that *argv[0]* will
be used for the *program* argument. You can also do this:

{% highlight python %}
device.spawn("/bin/busybox", argv=["/bin/cat", "/etc/passwd"])
{% endhighlight %}

And if you'd like to replace the entire environment instead of using defaults:

{% highlight python %}
device.spawn("/bin/ls", envp={ "CLICOLOR": "1" })
{% endhighlight %}

Though in most cases you probably only want to add/override a few environment
variables, which is now also possible:

{% highlight python %}
device.spawn("/bin/ls", env={ "CLICOLOR": "1" })
{% endhighlight %}

You might also want to use a different working directory:

{% highlight python %}
device.spawn("/bin/ls", cwd="/etc")
{% endhighlight %}

Or perhaps you'd like to redirect stdio:

{% highlight python %}
device.spawn("/bin/ls", stdio="pipe")
{% endhighlight %}

The *stdio* default value is *inherit*, as mentioned earlier.

We have now covered all of the *SpawnOptions*, except the last of them: *aux*.
This is a dictionary for platform-specific options. Setting such options is
pretty simple with the Python bindings: any keyword-argument not recognized
will end up in that dictionary.

For example, to launch Safari and tell it to open a specific URL:

{% highlight python %}
device.spawn("com.apple.mobilesafari", url="https://frida.re")
{% endhighlight %}

Or perhaps you'd like to spawn an i/macOS program with ASLR disabled:

{% highlight python %}
device.spawn("/bin/ls", aslr="disable")
{% endhighlight %}

Another example is spawning an Android app with a specific activity:

{% highlight python %}
spawn("com.android.settings", activity=".SecuritySettings")
{% endhighlight %}

And that's actually all of the aux options we currently support – and what's
great is that we can add new ones without needing to update our bindings.

But before we move on, let's take a quick look at what this new API would look
like using our Node.js bindings:

{% highlight js %}
const pid = await device.spawn('/bin/sh', {
  argv: ['/bin/sh', '-c', 'ls /'],
  env: {
    'BADGER': 'badger-badger-badger',
    'SNAKE': true,
    'MUSHROOM': 42,
  },
  cwd: '/usr',
  stdio: 'pipe',
  aslr: 'auto'
});
{% endhighlight %}

So as you can see, the second argument is an object with options, and those not
recognized end up in the aux dictionary.

### The rest

Let's just summarize the remaining changes, starting with the *Device* class:

- *enumerate_pending_spawns()* is now *enumerate_pending_spawn()* to be
  grammatically correct.
- The *spawned* signal has been renamed to *spawn-added*, and there is now also
  *spawn-removed*.
- The *delivered* signal has been renamed to *child-added*, and there is now
  also *child-removed*.

The final change is that the *Child* class' *path*, *argv*, and *envp*
properties are now all nullable. This is to be able to discern e.g. "no *envp*
provided" from "empty *envp* provided".

So that's about it. If you didn't read about the Frida 10.8 release that
happened last week, make sure you go read about it [here][].

Enjoy!


[API]: https://gist.github.com/oleavr/e6af8791adbef8fbde06
[Vala]: https://wiki.gnome.org/Projects/Vala
[GIO]: https://developer.gnome.org/gio/stable/ch02.html
[here]: /news/2018/04/28/frida-10-8-released/
