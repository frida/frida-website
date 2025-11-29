---
layout: news_item
title: 'Frida 17.3.2 发布'
date: 2025-09-19 17:16:32 +0200
author: oleavr
version: 17.3.2
categories: [release]
---

新鲜的比特准备好了！此版本专注于从我们的 Fruity 后端榨取更多性能：

- fruity: 批量数据报传递，使跨线程切换更具确定性并减少上下文切换开销。
- ncm: 重做 host→device 调度。我们现在保留一个 OUT 传输的滚动窗口，并在任何 URB 完成后立即重新填充，保持批量管道繁忙，并在我们的测试中将 HS 吞吐量从 ~29 MB/s 提高到 ~34 MB/s。
- ncm: 切换到固定槽 NDP 布局，将 O(k²) “收缩直到适合” 打包器变为 O(k)。在 256 MiB 传输中，这会将布局时间从 ~1.1 秒降低到本底噪声。

享受吧，让我们知道它对您的效果如何！
