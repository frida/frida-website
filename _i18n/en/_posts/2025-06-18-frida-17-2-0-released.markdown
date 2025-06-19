---
layout: news_item
title: 'Frida 17.2.0 Released'
date: 2025-06-18 23:35:07 +0200
author: oleavr
version: 17.2.0
categories: [release]
---

I'm thrilled to announce the release of Frida 17.2.0. This release focuses on
making package discovery dead-simple.

Here's how easy it is to discover existing Frida-specific packages:

![Terminal showing frida-pm search results](/img/frida-pm-search.png)

Consuming any of them is just as easy:

![Terminal showing frida-pm install results](/img/frida-pm-install.png)

**Highlights**

- 🔍 **frida-pm search** – zero-noise results (filters by `keywords:frida-gum`).
- 📦 **One-command install** – `frida-pm install <pkg>` works even without
  Node.js.
- 🧩 **Programmatic API** – identical surface from Python, C, etc.

What you see here is the frida-pm CLI tool, introduced in frida-tools 14.2.0.
It's less than 300 lines of Python code, as it's only a thin wrapper around the
underlying `Frida.PackageManager` implementation.

Power users and package maintainers will still typically use npm/yarn/etc., but
I feel like requiring first-time Frida users to also familiarize themselves with
the larger JavaScript ecosystem is likely to overwhelm and confuse.

What's neat about frida-pm / Frida.PackageManager is that searches only surface
Frida-specific packages. This is implemented by baking `keywords:frida-gum` into
the search query.

For those of you maintaining Frida-specific packages, make sure you add
`frida-gum` into your package.json's `keywords` field. If your package is a
language/runtime bridge, also make sure you add `frida-gum-bridge` as well.

So discoverability is one of the key features here. Another is that it can be
run on systems without Node.js + npm. While we do use npm's registry as our
default backend, you can point it at any registry you like.

You also get programmatic access to all of the functionality. For example, if
you want to use the Python bindings to make a search:

{% highlight py %}
import frida

pm = frida.PackageManager()
result = pm.search("il2cpp", limit=3)
print(result)
print(result.packages)
{% endhighlight %}

You'll see something like this:

{% highlight bash %}
$ python search.py
PackageSearchResult(packages=[<3 packages>], total=13)
[Package(name="frida-il2cpp-bridge", version="0.12.0", description="A Frida module to dump, trace or hijack any Il2Cpp application at runtime, without needing the global-metadata.dat file.", url="https://npm.im/frida-il2cpp-bridge"),
 Package(name="frida-objc-bridge", version="8.0.5", description="Objective-C runtime interop from Frida", url="https://npm.im/frida-objc-bridge"),
 Package(name="frida-java-bridge", version="7.0.4", description="Java runtime interop from Frida", url="https://npm.im/frida-java-bridge")]
$
{% endhighlight %}

Or perhaps you'd like to install a couple of packages:

{% highlight py %}
import frida

pm = frida.PackageManager()
result = pm.install(specs=["frida-java-bridge@7.0.4", "frida-il2cpp-bridge"])
print(result)
print(result.packages)
{% endhighlight %}

Which when run might look something like:

{% highlight bash %}
$ python install.py
PackageInstallResult(packages=[<2 packages>])
[Package(name="frida-java-bridge", version="7.0.4", description="Java runtime interop from Frida"),
 Package(name="frida-il2cpp-bridge", version="0.12.0", description="A Frida module to dump, trace or hijack any Il2Cpp application at runtime, without needing the global-metadata.dat file.")]
$
{% endhighlight %}

Installation progress is also easy to add:

{% highlight py %}
import frida

def on_install_progress(phase, fraction, details):
    print({
        "phase": phase,
        "fraction": fraction,
        "details": details,
    })

pm = frida.PackageManager()
pm.on("install-progress", on_install_progress)
result = pm.install(specs=["frida-java-bridge", "frida-il2cpp-bridge"])
print(result)
print(result.packages)
{% endhighlight %}

Which might look something like:

{% highlight bash %}
$ python install.py
{'phase': 'initializing', 'fraction': 0.0, 'details': None}
{'phase': 'preparing-dependencies', 'fraction': 0.05, 'details': None}
{'phase': 'resolving-package',
 'fraction': -1.0,
 'details': 'frida-java-bridge@latest'}
…
{% endhighlight %}

So now that we've looked at the PackageManager API being used from Python, I
should probably mention that it is (almost) just as easy to use this API from C:

{% highlight c %}
#include <frida-core.h>

int
main (int argc,
      char * argv[])
{
  GCancellable * cancellable = NULL;
  GError * error = NULL;

  frida_init ();

  FridaPackageManager * manager = frida_package_manager_new ();

  FridaPackageInstallOptions * opts = frida_package_install_options_new ();
  frida_package_install_options_add_spec (opts, "frida-java-bridge@7.0.4");
  frida_package_install_options_add_spec (opts, "frida-il2cpp-bridge");

  frida_package_manager_install_sync (manager, opts, cancellable, &error);
  if (error != NULL)
    g_printerr ("%s\n", error->message);

  return (error == NULL) ? 0 : 1;
}
{% endhighlight %}

If you want to give this example a try, grab a frida-core devkit from our
[releases][].

You can build and run it something like this:

{% highlight bash %}
$ gcc install.c -o install -I. -L. -lfrida-core -Wl,--gc-sections
$ ./install
{% endhighlight %}

(The top of frida-core-example.c has an example command-line tailored to the
specific OS/arch that the devkit is for.)

Note that `opts` can be omitted by passing NULL, in which case the packages
defined in package.json will be installed if they aren't already, or their
versions don't match. And just like with npm, if you don't have a package.json
file and simply go ahead and install some packages, a package.json will be
created for you.

This release also includes some other improvements and fixes:

- **Compiler**:
  - Bump `@frida/net` to 5.0.0.
  - Fix missing shim assets (thanks to [@imlihe][]).

- **frida-node**:
  - Change return type of `Device.openChannel()` to expose the more concrete
    type with `destroy()`.

To upgrade, go ahead and run:

{% highlight bash %}
$ pip install --upgrade frida frida-tools
{% endhighlight %}

Enjoy!


[releases]: https://github.com/frida/frida/releases
[@imlihe]: https://github.com/imlihe
