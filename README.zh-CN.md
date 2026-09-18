[![English](https://img.shields.io/badge/English-555555?style=flat)](README.md) [![简体中文](https://img.shields.io/badge/简体中文-555555?style=flat)](README.zh-CN.md)

# reboot-safety-check

用于 Linux 内核更新后的只读检查 CLI，在重启前排查 DKMS 模块问题，包括缺失或未完成的模块构建、缺少 kernel headers，以及 Secure Boot 签名风险。这些问题可能导致显卡、网络或其他树外驱动在重启后不可用。

![报告示例](docs/images/example-output.png)

## 安装

需要 Linux 和 Python 3.9+。程序使用 Python 标准库，读取本机系统信息。

```bash
git clone https://github.com/zhuhroscar-tech/reboot-safety-check.git
cd reboot-safety-check
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

[GitHub Releases](https://github.com/zhuhroscar-tech/reboot-safety-check/releases) 提供独立 `.pyz`；运行下载的文件前，请先核对 release 的 checksum。

## 使用

在包管理器安装新内核后运行：

```bash
reboot-safety-check
reboot-safety-check --json
reboot-safety-check --no-color
```

退出码：**0** 表示没有发现警告或失败项；**1** 表示有警告需要确认；**2** 表示发现失败项。请阅读具体结果再决定是否重启，退出码 0 不保证机器一定能正常启动。

## 检查内容

- 将 `/lib/modules` 中的内核与 `uname -r` 对比。逐内核检查仅针对版本排序高于当前运行内核的版本，而非所有未运行的内核。
- 读取 `dkms status`，检查已登记模块及其构建是否处于 installed 状态。若模块显示为 `installed` 但 dkms 自身附带"Diff between built and installed module"警告，或状态为 `broken`（缺少源码目录），会单独给出具体提示，而不是归入笼统的警告信息。
- 有相应工具时，通过 `dpkg-query` 或 `rpm` 查询匹配的 kernel headers。
- Secure Boot 启用时，通过 `mokutil` 检查已登记的 Machine Owner Key，并通过 `modinfo -k` 查找模块签名字段。

这些检查只能提供有限依据。存在签名字段并不能证明签名对应某个已登记且受信任的 key。工具缺失、输出无法识别或权限不足，都可能导致检查不完整。DKMS 不可用或未收集到条目时，可能没有可对比的模块，不能据此认为所有驱动均已验证。工具也不检查 bootloader、initramfs 或完整启动流程。

它不会安装模块、修改软件包、签名、登记 key 或重启；不联网，也不发送 telemetry。请按发行版的维护流程处理问题，并保留一个已知可用的备用内核。

## 开发

```bash
python -m pip install -e '.[dev]'
python -m pytest -v
```

[演示视频](docs/demo.mp4) · [MIT 许可证](LICENSE)。
