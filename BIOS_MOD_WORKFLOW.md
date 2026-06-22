# CVN B760M Frozen WIFI V20 1015 改版 BIOS 制作记录

本文记录本次改版 BIOS 的实际制作链路，目标是能从原版 BIOS 复现出可启动、可进系统、可由 `Client.exe` 调用的 SmmMem 版本。

## 1. 输入和工具

原版 BIOS：

```text
G:\Dev\SMM\_analysis\CVN B760M FROZEN WIFI V20 1015\CVN B760M FROZEN WIFI V20 1015\BIOS\CVN_B760M_FROZEN_WIFI_V20_1015.bin
SHA256: CA646282CFCB937CBDA40EBC4F066070DA4BF184FD634B102F83CE74CEDF20B2
```

替换工具：

```text
G:\Dev\SMM\tools\UEFIReplace.exe
```

用法：

```text
UEFIReplace.exe image_file guid section_type contents_file [-o output] [-all] [-asis]
```

这里全部替换 **PE32 Image section**，section type 是：

```text
10
```

关键点：**只替换 PE32 body，不替换 FFS 文件，不改 DEPEX**。

这样做的目的：

- 保留原模块 GUID / FFS 外壳 / UI name / version。
- 保留原 DEPEX，降低 BIOS 更新工具拒绝或启动依赖异常概率。
- 避免之前“换 DEPEX 后 BIOS 更新失败”的问题。

## 2. 自己构建 SmmMem

源码目录：

```text
G:\Dev\SMM\smm-mem-plouton
```

构建命令：

```powershell
cmd.exe /d /s /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul && "G:\Dev\SMM\smm-mem-plouton\src\build.cmd"'
```

产物：

```text
G:\Dev\SMM\smm-mem-plouton\Work\build\Dxe.efi
G:\Dev\SMM\smm-mem-plouton\Work\build\Smm.efi
G:\Dev\SMM\smm-mem-plouton\Work\build\Client.exe
```

其中：

- `Dxe.efi`：负责 DXE 阶段分配 mailbox、发布 ACPI/WMI 接口、把配置传给 SMM。
- `Smm.efi`：负责 SMI handler，执行读写内存、查进程、查模块、ringbench 等命令。
- `Client.exe`：Windows 用户态 CLI，通过 ACPI WMI 调用 DXE/SMM 通道。

## 3. 选择替换目标

### DXE 目标：EbcDxe

来自 `uefi_tree.txt`：

```text
GUID: 13ac6dd0-73d0-11d4-b06b-00aa00bd6de7
Name: EbcDxe
File type: 0x07 driver
Section 0: DXE dependency expression
Section 1: PE32 image section
```

替换方式：

```text
把 EbcDxe 的 PE32 image body 替换成 Dxe.efi
```

原因：

- 它是 DXE driver，适合放 DXE 侧 ACPI/WMI 发布逻辑。
- 原模块体积小、功能边缘，实测替换后可以正常启动。
- 不改 DEPEX，只换 PE32 body。

### SMM 目标：CmosSmm

来自 `uefi_tree.txt`：

```text
GUID: f44875ab-b9fc-4578-a280-aa335b49967c
Name: CmosSmm
File type: 0x0a system management
Section 0: SMM dependency expression
Section 1: PE32 image section
```

替换方式：

```text
把 CmosSmm 的 PE32 image body 替换成 Smm.efi
```

原因：

- 它本身是 SMM module。
- 原 DEPEX 已包含 SMM 基础依赖，包括 `EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID`。
- 只换 PE32 body 后，实测能正常开机进系统。

### PiSmmCpuDxeSmm 限制关闭

目标模块：

```text
GUID: a3ff0ef5-0c28-42f5-b544-8c7de1e80014
Name: PiSmmCpuDxeSmm
File type: 0x0a system management
Section 1: PE32 image section
```

补丁后 PE：

```text
G:\Dev\SMM\_analysis\pismmcpu_patch\PiSmmCpuDxeSmm_restricted_access_off.pe
```

作用：

```text
关闭/绕过 PiSmmCpuDxeSmm 的 SMM 代码访问限制，否则 SMM 访问系统地址时容易冻结或异常。
```

该补丁参考了 Plouton 文档里对 `PiSmmCpuDxeSmm` 的处理思路。

## 4. UEFIReplace 复现命令

下面是从原版 BIOS 重新生成 SmmMem 改版的命令模板。

```powershell
$UEFIReplace = "G:\Dev\SMM\tools\UEFIReplace.exe"
$Orig = "G:\Dev\SMM\_analysis\CVN B760M FROZEN WIFI V20 1015\CVN B760M FROZEN WIFI V20 1015\BIOS\CVN_B760M_FROZEN_WIFI_V20_1015.bin"
$Dxe = "G:\Dev\SMM\smm-mem-plouton\Work\build\Dxe.efi"
$Smm = "G:\Dev\SMM\smm-mem-plouton\Work\build\Smm.efi"
$PiSmmCpu = "G:\Dev\SMM\_analysis\pismmcpu_patch\PiSmmCpuDxeSmm_restricted_access_off.pe"

$Step1 = "G:\Dev\SMM\_analysis\smmmem_bios\step1_pismm.bin"
$Step2 = "G:\Dev\SMM\_analysis\smmmem_bios\step2_dxe.bin"
$Final = "G:\Dev\SMM\_analysis\smmmem_bios\final_smmmem.bin"

& $UEFIReplace $Orig  a3ff0ef5-0c28-42f5-b544-8c7de1e80014 10 $PiSmmCpu -o $Step1
& $UEFIReplace $Step1 13ac6dd0-73d0-11d4-b06b-00aa00bd6de7 10 $Dxe      -o $Step2
& $UEFIReplace $Step2 f44875ab-b9fc-4578-a280-aa335b49967c 10 $Smm      -o $Final
```

实际操作中也可以先替换 `EbcDxe/CmosSmm`，再替换 `PiSmmCpuDxeSmm`。这三个替换互相独立，核心要求是最终 BIOS 同时包含：

```text
EbcDxe PE32    -> Dxe.efi
CmosSmm PE32   -> Smm.efi
PiSmmCpu PE32  -> restricted_access_off.pe
```

## 5. 本次实际产物

最终测试使用的文件：

```text
H:\gai\七彩虹B760M_1015_SmmMem_RingBench无驱批量_缓存修复版_EbcDxe加Dxe_CmosSmm加Smm_PiSmmCpu限制关闭_不改DEPEX.bin
SHA256: F03ECB9F0064D5E565C8AACD078F5FBD30584AE6F61F507CAFD7BB27C233F9FA
```

当前 `_analysis\smmmem_bios` 里保留的早期 SmmMem 产物：

```text
G:\Dev\SMM\_analysis\smmmem_bios\final_smmmem_noserial_evtfix.bin
SHA256: DCF85E2703B90E1F7670E6EA2A3FCEC5896988690CC59AB5DB8C1D146F569F92
```

注意：`H:\gai` 里的 RingBench 缓存修复版是后续迭代过的最终测试件；`_analysis\smmmem_bios` 里的 `final_smmmem_noserial_evtfix.bin` 是较早的基线件。

## 6. 验证方式

刷入后进 Windows，先测基础通信：

```powershell
G:\Dev\SMM\smm-mem-plouton\Work\build\Client.exe ping
```

期望：

```text
pong
```

再测诊断：

```powershell
G:\Dev\SMM\smm-mem-plouton\Work\build\Client.exe diag
```

重点看：

```text
init=EFI_SUCCESS
list=EFI_SUCCESS
cr3off=EFI_SUCCESS
kernel_base=...
system=...
module_list=...
```

再测进程和模块：

```powershell
G:\Dev\SMM\smm-mem-plouton\Work\build\Client.exe findproc explorer.exe
G:\Dev\SMM\smm-mem-plouton\Work\build\Client.exe kernel ntoskrnl.exe
```

再测虚拟内存读取：

```powershell
G:\Dev\SMM\smm-mem-plouton\Work\build\Client.exe readvirt <pid> <image_base> 0x40
```

最后测 ringbench：

```powershell
G:\Dev\SMM\smm-mem-plouton\Work\build\Client.exe ringbench <pid> <image_base> 1000000 4060
```

已实测结果样例：

```text
completed=1000000
seconds=5.455024
ops_per_sec=183317.26
mib_per_sec=709.79
cycles_per_op=13610.39
```

## 7. 关键结论

这次能稳定进系统的关键不是“插入新模块”，而是：

```text
保留原 FFS/DEPEX，只替换 PE32 body。
```

最终 BIOS 的结构本质是：

```text
原版 BIOS
  + EbcDxe PE32 换成 SmmMem Dxe.efi
  + CmosSmm PE32 换成 SmmMem Smm.efi
  + PiSmmCpuDxeSmm PE32 换成 restricted_access_off.pe
  = SmmMem 改版 BIOS
```

