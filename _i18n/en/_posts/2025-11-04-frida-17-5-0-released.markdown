---
layout: news_item
title: 'Frida 17.5.0 Released'
date: 2025-11-04 14:02:32 +0100
author: oleavr
version: 17.5.0
categories: [release]
---

Fresh cups of ☕ and a heap of commits later, we’re back with a feature-packed
release. Highlights include a smarter compiler, sturdier Darwin internals, and
a massive Swift overhaul — the bindings are now async/await-first,
delegate-free, and largely platform-agnostic.

### Highlights

- **compiler**: Added `platform` and `externals` options to `CompilerOptions`,
  and plumbed them all the way down to the Go backend.
  This lets **frida-compile** (and `Frida.Compiler`) tailor its output to your
  target platform and treat selected modules as externals — e.g. when building
  a plugin for a GumJS agent, where the agent’s exposed API should be linked
  at runtime instead of bundled.
  (Thanks [@leonitousconforti][])
- **darwin**: Rewrote `query_shared_cache_range()` to parse the dyld shared
  cache header instead of walking VM regions from the base address found in
  `AllImageInfos`. This eliminates guesswork and ensures correct ranges even
  once pages get copy-on-written.
  (Thanks for the pair-programming, [@hsorbo][])
- **darwin**: `AllImageInfos` now reports the Dyld Shared Cache UUID and slide.
  (Thanks for the pair-programming, [@hsorbo][])
- **simmy**: `spawn()` grew proper `argv` and `env` wiring, so simulators now
  behave more like real devices.
- **frida-node**: Generated `from_value()` helpers now include inherited
  properties, so options like `externals` propagate correctly.
- **frida-python**: Fixed a tiny but leaky corner in `PackageManager` specs
  option parsing.

### Swift bindings: a modern, cross-platform makeover 🍎

The **Frida Swift bindings** have been extensively refactored to be idiomatic
Swift, concurrency-first, and cross-platform.

- **Async/await everywhere** — most APIs now use Swift Concurrency and support
  `Task` cancellation via `GCancellable`.
- **Delegates removed** — delegate-based callbacks have been replaced with
  **async event streams** (`AsyncStream`), making event handling ergonomic and
  composable.
- **Thread-friendly** — `api: Support invocation from any thread` enables safe
  invocation from non-main threads. (Thanks for the pair-programming,
  [@hsorbo][].)
- **Pure Swift core + cross-platform** — the core bindings are now
  Foundation and Dispatch-free and use pure Swift types (binary data represented
  as `[UInt8]`). Two small gaps remain: JSON encoding/decoding in the Marshal
  helpers currently use Foundation; a non-Foundation fallback will be added
  later.
- **SwiftUI-friendly** — the new `DeviceListModel`, a
  `@MainActor ObservableObject` that exposes `@Published devices` and
  `discoveryState` for smooth SwiftUI integration.
- **Icon portability** — platform-specific image handling replaced by a
  portable `Icon` enum with platform adapters for `CGImage`, `NSImage`,
  `UIImage`, and `SwiftUI.Image`.
- **API stability improvements** — public enums are annotated with `@frozen`
  and some complex reference types are marked `@unchecked Sendable` where
  necessary.

> Note: `frida-swift` prebuilt binaries are not included in this release; if
> you use the Swift bindings you should `git clone` and build from `main` to
> get the latest changes.
>
> Also note that the Swift bindings are still **experimental and evolving** —
> while the new APIs are a big leap forward, they may continue to change until
> the Swift layer stabilizes in an upcoming release.

### Quick examples (from the frida-swift README)

`DeviceListModel` (UI-friendly model):

```swift
import Combine

@MainActor
public final class DeviceListModel: ObservableObject {
    @Published public private(set) var devices: [Device] = []
    @Published public private(set) var discoveryState: DiscoveryState = .discovering

    @frozen
    public enum DiscoveryState: Equatable {
        case discovering
        case ready
    }

    public let manager: DeviceManager

    public init(manager: DeviceManager) { … }
}
```

Can now be used like this:

```swift
import Frida
import SwiftUI

struct DevicesView: View {
    @StateObject private var model = DeviceListModel(manager: DeviceManager())
    @State private var selectedDevice: Device?
    @State private var session: Session?

    var body: some View {
        NavigationStack {
            List(model.devices, id: \.id) { device in
                Button {
                    Task {
                        selectedDevice = device
                        session = try? await device.attach(to: 12345)
                    }
                } label: {
                    VStack(alignment: .leading) {
                        Text(device.name)
                            .font(.headline)
                        Text(device.kind.rawValue)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Frida Devices")
            .overlay {
                if model.devices.isEmpty {
                    ProgressView("Searching for devices…")
                }
            }
        }
    }
}
```

Full script lifecycle example:

```swift
func testFullCycle() async throws {
    let manager = DeviceManager()

    for await devices in await manager.snapshots() {
        guard let local = devices.first(where: { $0.kind == .local }) else {
            continue
        }

        let session = try await local.attach(to: 12345)
        let script = try await session.createScript("""
            console.log("hello");
            send(1337);
        """)

        Task {
            for await event in script.events {
                switch event {
                case .message(let message, _):
                    print("Message:", message)
                case .destroyed:
                    print("Script destroyed")
                }
            }
        }

        try await script.load()
        break
    }
}
```

Enjoy, and as always, let us know if you run into any bumps!


[@leonitousconforti]: https://github.com/leonitousconforti
[@hsorbo]: https://x.com/hsorbo
