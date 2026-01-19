## 目录

1. 构建 Frida
 - [先决条件](#先决条件)
 - [获取代码](#获取代码)
 - [为本机构建](#为本机构建)
 - [为不同机器构建](#为不同机器构建)
 - [树外构建](#树外构建)

## 构建 Frida

### 先决条件

你需要：

- C/C++ 工具链
- Node.js >= 18
- Git

例如在 Ubuntu 系统上：

{% highlight bash %}
$ sudo apt-get install build-essential git lib32stdc++-9-dev \
    libc6-dev-i386 nodejs npm
{% endhighlight %}

### 获取代码

{% highlight bash %}
$ git clone https://github.com/frida/frida.git
{% endhighlight %}

### 为本机构建

要构建，请运行：

{% highlight bash %}
$ make
{% endhighlight %}

这将使用 `./build` 作为构建目录。运行 `make install` 进行安装。

您也可以先运行 `./configure` 来指定 `--prefix` 或任何其他选项。使用 `--help` 列出顶级选项。

要设置较低级别的选项，请执行：

{% highlight bash %}
$ ./configure -- first-option second-option …
{% endhighlight %}

`--` 之后的选项直接传递给 Meson 的 `setup` 命令。这意味着您也可以将项目选项传递给子项目，例如：

{% highlight bash %}
$ ./configure -- \
    -Dfrida-gum:devkits=gum,gumjs \
    -Dfrida-core:devkits=core
{% endhighlight %}

有关可用选项，请查阅 subprojects/* 中的 `meson.options`。您也可以单独克隆不同的仓库，并按照此处描述的相同方式进行构建。

### 为不同机器构建

#### iOS/watchOS/tvOS

{% highlight bash %}
$ ./configure --host=ios-arm64
# or: ./configure --host=watchos-arm64
# or: ./configure --host=tvos-arm64
# optionally suffixed by `-simulator`
$ make
{% endhighlight %}

#### Android

{% highlight bash %}
$ ./configure --host=android-arm64
$ make
{% endhighlight %}

#### Raspberry Pi

{% highlight bash %}
$ sudo apt-get install g++-arm-linux-gnueabihf
$ ./configure --host=arm-linux-gnueabihf
$ make
{% endhighlight %}

### 树外构建

有时您可能希望使用单个源代码树为多个系统或配置进行构建。为此，请从源代码树外部的空目录调用 `configure`：

{% highlight bash %}
$ mkdir build-ios
$ ../frida/configure --host=ios-arm64
$ make
$ cd ..
$ mkdir build-android
$ ../frida/configure --host=android-arm64
$ make
{% endhighlight %}
