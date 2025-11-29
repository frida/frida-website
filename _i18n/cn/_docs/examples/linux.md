# Docker 上的 Linux
为了在 Docker 中使用 Linux 运行 Frida，您需要在没有 seccomp 的情况下启动容器，例如：
```
docker run --security-opt seccomp:unconfined -it <image name> /bin/bash
```
上面的命令将创建一个基于您指定的镜像的容器，禁用 seccomp，并运行一个交互式 shell。然后您可以使用 `frida-trace` 来测试 Frida。
