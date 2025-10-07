---
layout: docs
title: JavaScript
permalink: /docs/examples/javascript/
---

## Connect to a Node.js process' V8 VM to inject arbitrary JS

{% highlight js %}
const uv_default_loop = new NativeFunction(Module.getGlobalExportByName('uv_default_loop'), 'pointer', []);
const uv_async_init = new NativeFunction(Module.getGlobalExportByName('uv_async_init'), 'int', ['pointer', 'pointer', 'pointer']);
const uv_async_send = new NativeFunction(Module.getGlobalExportByName('uv_async_send'), 'int', ['pointer']);
const uv_close = new NativeFunction(Module.getGlobalExportByName('uv_close'), 'void', ['pointer', 'pointer']);
const uv_unref = new NativeFunction(Module.getGlobalExportByName('uv_unref'), 'void', ['pointer']);

const v8_Isolate_GetCurrent = new NativeFunction(Module.getGlobalExportByName('_ZN2v87Isolate10GetCurrentEv'), 'pointer', []);
const v8_Isolate_GetCurrentContext = new NativeFunction(Module.getGlobalExportByName('_ZN2v87Isolate17GetCurrentContextEv'), 'pointer', ['pointer']);

const v8_HandleScope_init = new NativeFunction(Module.getGlobalExportByName('_ZN2v811HandleScopeC1EPNS_7IsolateE'), 'void', ['pointer', 'pointer']);
const v8_HandleScope_finalize = new NativeFunction(Module.getGlobalExportByName('_ZN2v811HandleScopeD1Ev'), 'void', ['pointer']);

const v8_String_NewFromUtf8 = new NativeFunction(Module.getGlobalExportByName('_ZN2v86String11NewFromUtf8EPNS_7IsolateEPKcNS_13NewStringTypeEi'), 'pointer', ['pointer', 'pointer', 'int', 'int']);

const v8_Script_Compile = new NativeFunction(Module.getGlobalExportByName('_ZN2v86Script7CompileENS_5LocalINS_7ContextEEENS1_INS_6StringEEEPNS_12ScriptOriginE'), 'pointer', ['pointer', 'pointer', 'pointer']);
const v8_Script_Run = new NativeFunction(Module.getGlobalExportByName('_ZN2v86Script3RunENS_5LocalINS_7ContextEEE'), 'pointer', ['pointer', 'pointer']);

const NewStringType = {
  kNormal: 0,
  kInternalized: 1
};

const pending = [];

const processPending = new NativeCallback(function () {
  const isolate = v8_Isolate_GetCurrent();

  const scope = Memory.alloc(24);
  v8_HandleScope_init(scope, isolate);

  const context = v8_Isolate_GetCurrentContext(isolate);

  while (pending.length > 0) {
    const item = pending.shift();
    const source = v8_String_NewFromUtf8(isolate, Memory.allocUtf8String(item), NewStringType.kNormal, -1);
    const script = v8_Script_Compile(context, source, NULL);
    const result = v8_Script_Run(script, context);
  }

  v8_HandleScope_finalize(scope);
}, 'void', ['pointer']);

const onClose = new NativeCallback(function () {
  Script.unpin();
}, 'void', ['pointer']);

const handle = Memory.alloc(128);
uv_async_init(uv_default_loop(), handle, processPending);
uv_unref(handle);

Script.bindWeak(handle, () => {
  Script.pin();
  uv_close(handle, onClose);
});

function run(source) {
  pending.push(source);
  uv_async_send(handle);
}

run('console.log("Hello from Frida");');
{% endhighlight %}

## Trace function calls in a Perl 5 process

{% highlight js %}
const pointerSize = Process.pointerSize;
const SV_OFFSET_FLAGS = pointerSize + 4;
const PVGV_OFFSET_NAMEHEK = 4 * pointerSize;

const SVt_PVGV = 9;

Interceptor.attach(Module.getGlobalExportByName('Perl_pp_entersub'), {
  onEnter(args) {
    const interpreter = args[0];
    const stack = interpreter.readPointer();

    const sub = stack.readPointer();

    const flags = sub.add(SV_OFFSET_FLAGS).readU32();
    const type = flags & 0xff;
    if (type === SVt_PVGV) {
      /*
       * Note: this console.log() is not ideal performance-wise,
       * a proper implementation would buffer and submit events
       * periodically with send().
       */
      console.log(GvNAME(sub) + '()');
    } else {
      // XXX: Do we need to handle other types?
    }
  }
});

function GvNAME(sv) {
  const body = sv.readPointer();
  const nameHek = body.add(PVGV_OFFSET_NAMEHEK).readPointer();
  return nameHek.add(8).readUtf8String();
}
{% endhighlight %}

_Please click "Improve this page" above and add an example. Thanks!_
