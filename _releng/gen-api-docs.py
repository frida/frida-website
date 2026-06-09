#!/usr/bin/env python3
"""
Generate gi-docgen API reference sites for Frida's GObject-Introspection
libraries and drop them into the built Jekyll site.

For each configured library we:

  1. Obtain its ``.gir`` (from a local override or a GitHub release asset).
  2. Sanitize the GIR so gi-docgen can parse it (see ``sanitize_gir``).
  3. Run ``gi-docgen generate`` into ``_site/docs/<slug>/``.

The reference is structural: it reflects exactly the public API surface
captured in the GIR. Prose improves automatically as gtk-doc/valadoc
comments are added upstream in frida-gum and frida-core.

Usage:
    _releng/gen-api-docs.py [--output-dir _site/docs]

Local testing without network: point a library at a prebuilt GIR via
    GUM_GIR=/path/to/Gum-1.0.gir
    FRIDA_GIR=/path/to/Frida-1.0.gir
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

RELENG = Path(__file__).resolve().parent
REPO = RELENG.parent
CONFIG_ROOT = RELENG / "api-docs"
THEME_OVERLAY = CONFIG_ROOT / "theme"
THEME_NAME = "Frida"

GIR_NS = "http://www.gtk.org/introspection/core/1.0"

# Injected into the stock base.html at its (stable) block anchors so we don't
# have to fork the whole template. See build_theme(). We add a sidebar link
# back to the main docs (the sidebar is normal flow, so this lays out cleanly
# regardless of gi-docgen's fixed-sidebar styling) plus our override stylesheet.
SIDEBAR_HTML = (
    '<div class="section frida-nav">'
    '<a href="https://frida.re/docs/home/">&larr; Frida Docs</a>'
    "</div>\n      "
)
STYLE_LINK = '<link rel="stylesheet" href="frida-overrides.css" type="text/css" />'

# Each library is generated independently. ``gir_env`` lets a developer point
# at a locally built GIR; ``gir_url`` is the canonical CI/release source.
LIBRARIES = [
    {
        "slug": "gum",
        "namespace": "Gum-1.0",
        "gir_filename": "Gum-1.0.gir",
        "gir_env": "GUM_GIR",
        "gir_url": "https://github.com/frida/frida-gum/releases/latest/download/Gum-1.0.gir",
    },
    {
        "slug": "frida-core",
        "namespace": "Frida-1.0",
        "gir_filename": "Frida-1.0.gir",
        "gir_env": "FRIDA_GIR",
        "gir_url": "https://github.com/frida/frida-core/releases/latest/download/Frida-1.0.gir",
    },
]


def main():
    parser = argparse.ArgumentParser(description="Generate Frida API reference docs.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO / "_site" / "docs",
        help="Directory to write per-library doc sites into (default: _site/docs).",
    )
    parser.add_argument(
        "--include-path",
        action="append",
        default=[],
        help="Extra directory to search for dependency GIRs (repeatable).",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="Generate only these library slugs (repeatable).",
    )
    parser.add_argument(
        "--version",
        default=os.environ.get("FRIDA_VERSION"),
        help="Release version to display in the docs (e.g. 17.11.1). "
        "Defaults to $FRIDA_VERSION, then the GIR's API version.",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Warn and skip a library whose GIR can't be obtained, instead of "
        "failing. Use in CI until the producers publish GIR release assets.",
    )
    args = parser.parse_args()

    if shutil.which("gi-docgen") is None:
        sys.exit("error: gi-docgen not found on PATH (pip install gi-docgen)")

    include_paths = list(args.include_path) + default_include_paths()

    libraries = LIBRARIES
    if args.only:
        libraries = [lib for lib in libraries if lib["slug"] in args.only]

    with tempfile.TemporaryDirectory(prefix="frida-girs-") as workdir:
        workdir = Path(workdir)
        templates_dir = build_theme(workdir)
        generated = 0
        for lib in libraries:
            ok = generate_library(
                lib, args.output_dir, include_paths, workdir, templates_dir,
                args.version, args.allow_missing,
            )
            generated += int(ok)

    print(f"API reference generation complete ({generated}/{len(libraries)} libraries).")


def build_theme(workdir):
    """Compose the Frida gi-docgen theme from the installed 'basic' theme.

    Rather than fork ~50 template files, we copy the stock theme and patch only
    base.html's stable block anchors (style_other, footer) plus the body, and
    drop in our frida-overrides.css. Returns the templates dir to pass via
    --templates-dir (the theme itself lives in <dir>/frida, per gi-docgen's
    name.lower() convention).
    """
    import importlib.util

    spec = importlib.util.find_spec("gidocgen")
    if spec is None or spec.origin is None:
        sys.exit("error: cannot locate the gidocgen package to build the theme")
    basic = Path(spec.origin).parent / "templates" / "basic"
    if not basic.is_dir():
        sys.exit(f"error: gidocgen 'basic' theme not found at {basic}")

    templates_dir = workdir / "templates"
    theme_dir = templates_dir / THEME_NAME.lower()
    shutil.copytree(basic, theme_dir)

    # Overlay our branding stylesheet.
    shutil.copy(THEME_OVERLAY / "frida-overrides.css", theme_dir / "frida-overrides.css")

    # Patch base.html at gi-docgen's stable block anchors.
    base = theme_dir / "base.html"
    html = base.read_text(encoding="utf-8")
    html = patch_once(base, html,
                      "{% block style_other %}",
                      "{% block style_other %}\n  " + STYLE_LINK)
    html = patch_once(base, html,
                      "{% block sidebar %}",
                      SIDEBAR_HTML + "{% block sidebar %}")
    base.write_text(html, encoding="utf-8")

    # Register the theme under its own name and ship the overlay CSS.
    toml = (theme_dir / "basic.toml").read_text(encoding="utf-8")
    toml = toml.replace('name = "Basic"', f'name = "{THEME_NAME}"', 1)
    toml = toml.replace('files = [\n', 'files = [\n  "frida-overrides.css",\n', 1)
    (theme_dir / f"{THEME_NAME.lower()}.toml").write_text(toml, encoding="utf-8")

    print(f"==> composed '{THEME_NAME}' theme from {basic}")
    return templates_dir


def patch_once(path, html, anchor, replacement):
    if anchor not in html:
        sys.exit(
            f"error: theme anchor not found in {path.name}: {anchor!r}\n"
            f"       (gi-docgen's base.html changed; update build_theme())"
        )
    return html.replace(anchor, replacement, 1)


def generate_library(lib, output_dir, include_paths, workdir, templates_dir,
                     version_override=None, allow_missing=False):
    slug = lib["slug"]
    print(f"==> {slug}: obtaining {lib['gir_filename']}")
    raw_gir = obtain_gir(lib, workdir, allow_missing)
    if raw_gir is None:
        print(f"    !! skipping {slug}: GIR unavailable")
        return False

    print(f"    sanitizing GIR")
    clean_gir = workdir / f"{slug}-clean.gir"
    api_version = sanitize_gir(raw_gir, clean_gir)
    version = version_override or api_version
    print(f"    version {version} (GIR API version {api_version})")

    config = CONFIG_ROOT / slug / "config.toml"
    if not config.exists():
        sys.exit(f"error: missing config for {slug}: {config}")
    config = inject_version(config, version, workdir / f"{slug}-config.toml")

    dest = output_dir / slug
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "gi-docgen",
        "generate",
        "--quiet",
        "--no-namespace-dir",
        "--config",
        str(config),
        "--templates-dir",
        str(templates_dir),
        "--theme-name",
        THEME_NAME.lower(),
        "--output-dir",
        str(dest),
    ]
    for path in include_paths:
        cmd += ["--add-include-path", str(path)]
    cmd.append(str(clean_gir))

    print(f"    running gi-docgen -> {dest}")
    subprocess.run(cmd, check=True)
    return True


def inject_version(config_src, version, config_dest):
    """Write a copy of the config with the real library version substituted.

    gi-docgen has no version-override flag; it reads ``[library] version``
    from the config, so we rewrite the placeholder line per run.
    """
    lines = config_src.read_text(encoding="utf-8").splitlines(keepends=True)
    out = []
    replaced = False
    for line in lines:
        if not replaced and line.lstrip().startswith("version"):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f'{indent}version = "{version}"\n')
            replaced = True
        else:
            out.append(line)
    config_dest.write_text("".join(out), encoding="utf-8")
    return config_dest


def obtain_gir(lib, workdir, allow_missing=False):
    override = os.environ.get(lib["gir_env"])
    if override:
        src = Path(override)
        if not src.exists():
            sys.exit(f"error: {lib['gir_env']}={src} does not exist")
        return src

    dest = workdir / lib["gir_filename"]
    url = lib["gir_url"]
    print(f"    downloading {url}")
    try:
        urllib.request.urlretrieve(url, dest)
    except Exception as e:
        msg = (
            f"failed to download GIR for {lib['slug']} from {url}: {e}\n"
            f"       (set {lib['gir_env']}=/path/to/{lib['gir_filename']} to use a local copy)"
        )
        if allow_missing:
            print(f"    warning: {msg}")
            return None
        sys.exit(f"error: {msg}")
    return dest


def sanitize_gir(src, dest):
    """Make a GIR safe for gi-docgen and return the library version.

    Two classes of breakage observed against real Frida GIRs:

      * Non-introspectable constants (e.g. GUM_DEFAULT_CS_MODE, which is
        ``(skip)``-annotated upstream) are still emitted with
        ``introspectable="0"`` and a nameless ``<type>``. gi-docgen's
        constant parser crashes on the missing ``name`` attribute. We drop
        any node explicitly marked ``introspectable="0"``.

      * A handful of public symbols expose third-party types (Capstone:
        cs_mode/csh/cs_insn) as ``<type>`` elements with no ``name``. We
        give any remaining nameless ``<type>`` a ``gpointer`` fallback so
        the parser stays happy; such symbols can't be used from bindings
        anyway and read as opaque pointers in the reference.

      * frida-core's ``<doc>`` elements are synthesized by its api/generate.py
        and lack the ``filename``/``line`` attributes that g-ir-scanner always
        emits; gi-docgen accesses both unconditionally and crashes with a
        ``KeyError`` otherwise. We backfill them where missing.
    """
    ET.register_namespace("", GIR_NS)
    for prefix, uri in {
        "c": "http://www.gtk.org/introspection/c/1.0",
        "glib": "http://www.gtk.org/introspection/glib/1.0",
    }.items():
        ET.register_namespace(prefix, uri)

    tree = ET.parse(src)
    root = tree.getroot()

    # Drop nodes flagged non-introspectable; they are not part of the
    # bindable surface and routinely carry malformed type references.
    drop_non_introspectable(root)

    # Backstop: any nameless <type> left over gets a fallback name.
    fallback_nameless_types(root)

    # Ensure every <doc> carries the source attributes gi-docgen requires.
    fixup_doc_source_attrs(root)

    version = "0.0.0"
    ns = root.find(f"{{{GIR_NS}}}namespace")
    if ns is not None:
        version = ns.get("version", version)

    tree.write(dest, encoding="utf-8", xml_declaration=True)
    return version


def drop_non_introspectable(parent):
    for child in list(parent):
        if child.get("introspectable") == "0":
            parent.remove(child)
        else:
            drop_non_introspectable(child)


def fallback_nameless_types(parent):
    for child in parent.iter(f"{{{GIR_NS}}}type"):
        if child.get("name") is None:
            child.set("name", "gpointer")


def fixup_doc_source_attrs(parent):
    for doc in parent.iter(f"{{{GIR_NS}}}doc"):
        if doc.get("filename") is None:
            doc.set("filename", "<generated>")
        if doc.get("line") is None:
            doc.set("line", "0")


def default_include_paths():
    """Directories where dependency GIRs (GLib/GObject/Gio/...) may live."""
    paths = []
    # System gobject-introspection (Debian/Ubuntu CI: gobject-introspection pkg).
    for candidate in ("/usr/share/gir-1.0", "/usr/local/share/gir-1.0"):
        if Path(candidate).is_dir():
            paths.append(candidate)
    return paths


if __name__ == "__main__":
    main()
