---
layout: news_item
title: 'Frida 17.5.0 发布'
date: 2025-11-04 14:02:32 +0100
author: oleavr
version: 17.5.0
categories: [release]
---

喝了几杯 ☕ 并提交了一堆代码后，我们带着功能丰富的版本回来了。亮点包括更智能的编译器、更稳固的 Darwin 内部结构以及大规模的 Swift 改革 —— 绑定现在是 async/await 优先、无委托且很大程度上与平台无关的。

### 亮点

- **compiler**: 向 `CompilerOptions` 添加了 `platform` 和 `externals` 选项，并将它们一直传递到 Go 后端。
  这让 **frida-compile** (和 `Frida.Compiler`) 可以根据你的目标平台定制输出，并将选定的模块视为外部模块 —— 例如，在为 GumJS 代理构建插件时，代理公开的 API 应该在运行时链接而不是打包在一起。
  (感谢 [@leonitousconforti][])
- **darwin**: 重写了 `query_shared_cache_range()` 以解析 dyld 共享缓存头，而不是从 `AllImageInfos` 中找到的基地址遍历 VM 区域。这消除了猜测，即使页面被写时复制也能确保范围正确。
  (感谢结对编程，[@hsorbo][])
- **darwin**: `AllImageInfos` 现在报告 Dyld 共享缓存 UUID 和 slide。
  (感谢结对编程，[@hsorbo][])
- **simmy**: `spawn()` 增加了正确的 `argv` 和 `env` 连接，因此模拟器现在的行为更像真实设备。
- **frida-node**: 生成的 `from_value()` 助手现在包含继承的属性，因此像 `externals` 这样的选项可以正确传播。
- **frida-python**: 修复了 `PackageManager` 规范选项解析中一个微小但会导致泄漏的角落情况。

### Swift 绑定：现代、跨平台的改造 🍎

**Frida Swift 绑定** 已经被广泛重构，以符合 Swift 惯用语、并发优先且跨平台。

- **到处都是 Async/await** — 大多数 API 现在使用 Swift Concurrency 并支持通过 `GCancellable` 进行 `Task` 取消。
- **移除委托** — 基于委托的回调已被 **异步事件流** (`AsyncStream`) 取代，使事件处理符合人体工程学且可组合。
- **线程友好** — `api: Support invocation from any thread` 允许从非主线程安全调用。(感谢结对编程，[@hsorbo][]。)
- **纯 Swift 核心 + 跨平台** — 核心绑定现在不依赖 Foundation 和 Dispatch，并使用纯 Swift 类型 (二进制数据表示为 `[UInt8]`)。目前还有两个小缺口：Marshal 助手中的 JSON 编码/解码目前使用 Foundation；稍后将添加非 Foundation 回退。
- **SwiftUI 友好** — 新的 `DeviceListModel`，一个 `@MainActor ObservableObject`，公开 `@Published devices` 和 `discoveryState` 以实现流畅的 SwiftUI 集成。
- **图标可移植性** — 平台特定的图像处理已被可移植的 `Icon` 枚举取代，带有用于 `CGImage`、`NSImage`、`UIImage` 和 `SwiftUI.Image` 的平台适配器。
- **API 稳定性改进** — 公共枚举用 `@frozen` 注释，一些复杂的引用类型在必要时标记为 `@unchecked Sendable`。

> 注意：此版本不包含 `frida-swift` 预构建二进制文件；如果你使用 Swift 绑定，你应该 `git clone` 并从 `main` 构建以获取最新更改。
>
> 另外请注意，Swift 绑定仍然是 **实验性的和不断发展的** — 虽然新 API 是一个巨大的飞跃，但在即将发布的版本中 Swift 层稳定之前，它们可能会继续更改。

### 快速示例 (来自 frida-swift README)

`DeviceListModel` (UI 友好模型):

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

现在可以像这样使用：

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

完整的脚本生命周期示例：

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

享受吧，一如既往，如果你遇到任何问题，请告诉我们！


[@leonitousconforti]: https://github.com/leonitousconforti
[@hsorbo]: https://x.com/hsorbo
