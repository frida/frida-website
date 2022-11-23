このサイトはfridaのわかりやすいガイドを目指しています。
例えば、コマンドラインから対話的に関数のトレースを行う方法や
FridaのAPIを用いて独自のツールを開発する方法について紹介していきます。

## Fridaとは

Fridaは[Greasemonkey](https://addons.mozilla.org/en-US/firefox/addon/greasemonkey/)のネイティブアプリケーション版です。より技術的な用語で言うとするならば、動的解析ツールキットです。
Fridaを使うことで、Windows、macOS、GNU/Linux、iOS、watchOS、tvOS、Android、FreeBSDやQNXのネイティブアプリケーションに対してJavascriptコードやライブラリをインジェクトすることができます。また、FridaはFrida API上に構築されたいくつかのツールを提供します。
これらをそのまま使用するのももちろんこと、必要に応じて調整したり、Frida APIの使用例として使うこともできます。

## なぜこれが必要なの？

良い質問ですね！いくつかのユースケースを使用して明確にしていきます:

- There's this new hot app everybody's so excited about, but it's only
  available for iOS and you'd love to interop with it. You realize it's
  relying on encrypted network protocols and tools like Wireshark just
  won't cut it. You pick up Frida and use it for API tracing.
- You're building a desktop app which has been deployed at a customer's site.
  There's a problem but the built-in logging code just isn't enough. You
  need to send your customer a custom build with lots of expensive logging
  code. Then you realize you could just use Frida and build an application-
  specific tool that will add all the diagnostics you need, and in just a
  few lines of Python. No need to send the customer a new custom build - you
  just send the tool which will work on many versions of your app.
- You'd like to build a Wireshark on steroids with support for sniffing
  encrypted protocols. It could even manipulate function calls to fake network
  conditions that would otherwise require you to set up a test lab.
- Your in-house app could use some black-box tests without polluting your
  production code with logic only required for exotic testing.

## Why a Python API, but JavaScript debugging logic?

Frida's core is written in C and injects [QuickJS](https://bellard.org/quickjs/)
into the target processes, where your JS gets executed with full access to
memory, hooking functions and even calling native functions inside the process.
There's a bi-directional communication channel that is used to talk between your
app and the JS running inside the target process.

Using Python and JS allows for quick development with a risk-free API. Frida can
help you easily catch errors in JS and provide you an exception rather than
crashing.

Rather not write in Python?  No problem.  You can use Frida from C directly, and
on top of this C core there are multiple language bindings, e.g.
[Node.js](https://github.com/frida/frida-node),
[Python](https://github.com/frida/frida-python),
[Swift](https://github.com/frida/frida-swift),
[.NET](https://github.com/frida/frida-clr),
[Qml](https://github.com/frida/frida-qml), etc.  It is very easy to build
additional bindings for other languages and environments.

## ProTips™, Notes, and Warnings

Throughout this guide there are a number of small-but-handy pieces of
information that can make using Frida easier, more interesting, and less
hazardous. Here’s what to look out for.

<div class="note">
  <h5>ProTips™ help you get more from Frida</h5>
  <p>These are tips and tricks that will help you be a Frida wizard!</p>
</div>

<div class="note info">
  <h5>Notes are handy pieces of information</h5>
  <p>These are for the extra tidbits sometimes necessary to understand
     Frida.</p>
</div>

<div class="note warning">
  <h5>Warnings help you not blow things up</h5>
  <p>Be aware of these messages if you wish to avoid certain death.</p>
</div>

If you come across anything along the way that we haven’t covered, or if you
know of a tip you think others would find handy, please [file an
issue]({{ site.organization_url }}/frida-website/issues/new), and we’ll see about
including it in this guide.
