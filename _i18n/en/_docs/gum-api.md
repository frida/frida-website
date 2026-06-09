The **frida-gum** library is Frida's C core for instrumentation: hooking and
replacing functions ([Interceptor](/docs/gum/class.Interceptor.html)), tracing
execution ([Stalker](/docs/gum/class.Stalker.html)), scanning and manipulating
memory, resolving symbols, and more.

## Reference

The full Gum API reference is auto-generated from the library's GObject
Introspection data, so it always matches the current release:

<p>
  <a class="btn" href="/docs/gum/">Browse the Gum API reference &rarr;</a>
</p>

The reference covers every class, method, signal, property, enumeration, and
constant in the public API. It is generated with
[gi-docgen](https://gnome.pages.gitlab.gnome.org/gi-docgen/) from the
`Gum-1.0.gir` produced by frida-gum's build.

> The reference reflects the API surface exactly. Prose descriptions are filled
> in over time as documentation comments are added to the frida-gum sources —
> [contributions welcome](https://github.com/frida/frida-gum).

## Using it from C

See the [C API](/docs/c-api/) overview for how the modules fit together and how
to obtain the devkits, which bundle the headers and a worked example for each
module.
