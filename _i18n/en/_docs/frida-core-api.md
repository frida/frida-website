The **frida-core** library is Frida's main injection and orchestration layer:
enumerate devices, attach to processes, create and manage sessions, load
scripts, and drive the compiler, all from C (and any language with GObject
Introspection bindings).

## Reference

The full Core API reference is auto-generated from the library's GObject
Introspection data, so it always matches the current release:

<p>
  <a class="btn" href="/docs/frida-core/">Browse the Core API reference &rarr;</a>
</p>

The reference covers every class, method, signal, property, enumeration, and
constant in the public API. It is generated with
[gi-docgen](https://gnome.pages.gitlab.gnome.org/gi-docgen/) from the
`Frida-1.0.gir` produced by frida-core's build.

> The reference reflects the API surface exactly. Prose descriptions are filled
> in over time as documentation comments are added to the frida-core sources —
> [contributions welcome](https://github.com/frida/frida-core).

## Using it from C

See the [C API](/docs/c-api/) overview for how the modules fit together and how
to obtain the devkits, which bundle the headers and a worked example.
