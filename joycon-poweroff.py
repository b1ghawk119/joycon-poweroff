#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
joycon-poweroff — 把 Nintendo Switch 手柄关到出厂态（Linux / Windows）

零依赖：只用 Python 3 标准库。不装 hidapi、不编译、不改系统目录。

  Linux   直接读写 /dev/hidraw（sysfs 枚举 + select）
  Windows 用 ctypes 调 SetupAPI / hid.dll（重叠 I/O 做超时读）

协议参考：
    Nintendo Switch 逆向工程笔记（子命令与 SPI flash 布局）
    https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering

协议：每条命令都是一个 64 字节的 output report
    buf[0]     = 0x01        report ID
    buf[1]     = 包序号 0..15
    buf[2..9]  = 震动数据（固定值）
    buf[10]    = 子命令
    buf[11..]  = 参数

发送序列：
    0x03 3F   切 Simple HID 输入模式（减少读噪声）
    0x30 F0   4 个灯全闪 —— 人工确认确实是蓝牙连接
    0x07      初始化 SPI 0x2000 段（清配对信息）
    0x08 01   写 0x01 @ SPI 0x5000（装运低功耗标志）
    0x10      回读校验 SPI 0x5000 == 0x01
    0x10      回读校验 SPI 0x2000 配对槽魔数已不是 0x95
    0x05      查主机列表状态（仅打印参考，不作判据）
    0x06 00   断开 → 触发 HID OFF，立即断电

每一步都必须拿到正确确认才继续：0x07 / 0x08 要求确认字节 0x80，0x10
回读要求同时匹配确认字节 0x90、回显地址和返回长度。任何一步校验不过就
中止，不发 0x06，并把手柄切回标准输入模式（0x03 30）。

为什么任何退出路径都要切回 0x30：0x3F（Simple HID）只在按键变化时上报，
而系统的 HID 驱动通常不认它（Linux hid-nintendo 的 read_handler 只处理
0x21 / 0x30 / 0x31）。停在 0x3F 的手柄看着还连着，但按键会全部失灵，
必须断开重连才恢复。

为什么 0x07 和 0x08 缺一不可：
    只发 0x08 01 → 配对信息还在，长按某些键仍能唤醒，电池照样漏。
    只发 0x07    → 低功耗标志没设，手柄仍是普通 SLEEP，一两周掉光。
    两条都发     → 断开后进 HID OFF 且按不醒，才是真正出厂态。

注意：Switch 每次连上手柄都会发 0x08 00 撤销这个标志，连回去就恢复原状。
"""

import argparse
import glob
import os
import select
import struct
import sys
import time

NINTENDO_VID = 0x057E
PIDS = {
    0x2006: "Joy-Con (L)",
    0x2007: "Joy-Con (R)",
    0x2009: "Pro Controller",
    0x2017: "SNES Controller",
    0x2019: "N64 Controller",
}

RUMBLE = bytes([0x00, 0x01, 0x40, 0x40, 0x00, 0x01, 0x40, 0x40])

SUB_INPUT_MODE = 0x03
SUB_PAGE_LIST = 0x05
SUB_HCI_STATE = 0x06
SUB_RESET_PAIR = 0x07
SUB_SHIPMENT = 0x08
SUB_SPI_READ = 0x10
SUB_LEDS = 0x30

SPI_PAIRING = 0x2000    # 配对信息段，0x07 初始化它
SPI_SHIPMENT = 0x5000   # 装运标志，0x08 01 写 0x01

PAIRING_SLOT = 0x26     # 每个配对槽占 0x26 字节（见协议笔记的 spi_flash_notes）
PAIRING_SLOTS = 2       # 抽查前 2 个槽：槽 1 是当前配对，槽 1 为 0x00 时槽 2 才是
PAIRING_MAGIC = 0x95    # 槽首字节：0x95 = 有效配对记录
SPI_READ_MAX = 0x1D     # 0x10 单次读取最大字节数
DRAIN_MAX = 64          # 每次发命令前最多丢弃多少条积压报告

ACK_OK = 0x80           # 普通子命令的确认字节（回复的 byte 13）
ACK_SPI_READ = 0x90     # 0x10 SPI 读取的确认字节

REPORT_LEN = 64
BUS_NAMES = {"0005": "bluetooth", "0003": "usb"}

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    # Windows 控制台默认用系统 ANSI 编码（简体中文是 GBK）。输出被重定向时
    # Python 会用它，而脚本里的 ✓ ✗ ⚠ 在 GBK 里不存在，会直接抛
    # UnicodeEncodeError 把脚本打断。统一改成 UTF-8，并允许替换无法编码的字符。
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


# ==================== Windows 后端（ctypes + SetupAPI） ====================
#
# 只用 Windows 自带的 DLL：setupapi / hid / cfgmgr32 / kernel32。
# 不需要 hidapi，不需要安装任何东西。
#
# 与 Linux 后端的对应关系：
#   枚举    /sys/class/hidraw/*          -> SetupDiGetClassDevsW 遍历 HID 接口
#   总线    uevent 里的 HID_ID           -> 走设备树看第一个祖先的 enumerator
#   唯一 ID uevent 里的 HID_UNIQ         -> HidD_GetSerialNumberString
#   打开    os.open                      -> CreateFileW
#   读      select + os.read             -> 重叠 I/O（OVERLAPPED + WaitForSingleObject）
#   写      os.write                     -> WriteFile

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _DIGCF_PRESENT = 0x02
    _DIGCF_DEVICEINTERFACE = 0x10
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ = 0x01
    _FILE_SHARE_WRITE = 0x02
    _OPEN_EXISTING = 3
    _FILE_FLAG_OVERLAPPED = 0x40000000   # 重叠 I/O 必需，否则 ReadFile 会阻塞
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _ERROR_IO_PENDING = 997
    _ERROR_IO_INCOMPLETE = 996
    _ERROR_NO_MORE_ITEMS = 259
    _ERROR_ACCESS_DENIED = 5
    _ERROR_INSUFFICIENT_BUFFER = 122
    _CLOSE_WAIT_MS = 3000      # close() 等取消生效的上限
    _WRITE_WAIT_MS = 3000      # 写操作的等待上限

    # 取消/等待超时后，内核可能仍在写这些 buf / OVERLAPPED。微软文档要求
    # 在操作真正完成前不得释放或重用它们。所以宁可故意扣住不放——泄漏几个
    # 缓冲区，远好过内核写已释放的内存。
    #
    # 注意：光靠模块级变量不够。Python 退出时会先清模块全局再结束进程，
    # 那会把这些对象释放掉。所以 __main__ 里用 os._exit() 跳过解释器清理，
    # 直接让进程结束、由系统回收。
    _QUARANTINE = []
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 258
    _HIDP_STATUS_SUCCESS = 0x110000

    class _GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    _GUID_DEVINTERFACE_HID = _GUID(
        0x4D1E55B2, 0xF16F, 0x11CF,
        (ctypes.c_ubyte * 8)(0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30))

    class _SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("InterfaceClassGuid", _GUID),
                    ("Flags", wintypes.DWORD),
                    ("Reserved", ctypes.POINTER(ctypes.c_ulong))]

    class _SP_DEVINFO_DATA(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("ClassGuid", _GUID),
                    ("DevInst", wintypes.DWORD),
                    ("Reserved", ctypes.POINTER(ctypes.c_ulong))]

    class _HIDD_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Size", wintypes.ULONG), ("VendorID", wintypes.USHORT),
                    ("ProductID", wintypes.USHORT),
                    ("VersionNumber", wintypes.USHORT)]

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_void_p),
                    ("InternalHigh", ctypes.c_void_p),
                    ("Offset", wintypes.DWORD),
                    ("OffsetHigh", wintypes.DWORD),
                    ("hEvent", wintypes.HANDLE)]

    class _HIDP_CAPS(ctypes.Structure):
        _fields_ = [("Usage", wintypes.USHORT), ("UsagePage", wintypes.USHORT),
                    ("InputReportByteLength", wintypes.USHORT),
                    ("OutputReportByteLength", wintypes.USHORT),
                    ("FeatureReportByteLength", wintypes.USHORT),
                    ("Reserved", wintypes.USHORT * 17),
                    ("NumberLinkCollectionNodes", wintypes.USHORT),
                    ("NumberInputButtonCaps", wintypes.USHORT),
                    ("NumberInputValueCaps", wintypes.USHORT),
                    ("NumberInputDataIndices", wintypes.USHORT),
                    ("NumberOutputButtonCaps", wintypes.USHORT),
                    ("NumberOutputValueCaps", wintypes.USHORT),
                    ("NumberOutputDataIndices", wintypes.USHORT),
                    ("NumberFeatureButtonCaps", wintypes.USHORT),
                    ("NumberFeatureValueCaps", wintypes.USHORT),
                    ("NumberFeatureDataIndices", wintypes.USHORT)]

    def _win_dlls():
        """加载并声明所有用到的原生函数。

        每个函数的 argtypes/restype 都必须写全：ctypes 默认把返回值当 int，
        64 位下会把句柄截断成 32 位。
        """
        setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
        hid = ctypes.WinDLL("hid", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        cfgmgr32 = ctypes.WinDLL("cfgmgr32", use_last_error=True)

        setupapi.SetupDiGetClassDevsW.argtypes = [
            ctypes.POINTER(_GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD]
        setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE

        setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_SP_DEVINFO_DATA),
            ctypes.POINTER(_GUID), wintypes.DWORD,
            ctypes.POINTER(_SP_DEVICE_INTERFACE_DATA)]
        setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL

        setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_SP_DEVICE_INTERFACE_DATA),
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(_SP_DEVINFO_DATA)]
        setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL

        setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
        setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

        cfgmgr32.CM_Get_Parent.argtypes = [
            ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.ULONG]
        cfgmgr32.CM_Get_Parent.restype = wintypes.DWORD

        cfgmgr32.CM_Get_Device_ID_Size.argtypes = [
            ctypes.POINTER(wintypes.ULONG), wintypes.DWORD, wintypes.ULONG]
        cfgmgr32.CM_Get_Device_ID_Size.restype = wintypes.DWORD

        cfgmgr32.CM_Get_Device_IDW.argtypes = [
            wintypes.DWORD, ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
        cfgmgr32.CM_Get_Device_IDW.restype = wintypes.DWORD

        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel32.CreateFileW.restype = wintypes.HANDLE

        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        kernel32.ReadFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(_OVERLAPPED)]
        kernel32.ReadFile.restype = wintypes.BOOL

        kernel32.WriteFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(_OVERLAPPED)]
        kernel32.WriteFile.restype = wintypes.BOOL

        kernel32.GetOverlappedResult.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_OVERLAPPED),
            ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
        kernel32.GetOverlappedResult.restype = wintypes.BOOL

        kernel32.CreateEventW.argtypes = [
            ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.CreateEventW.restype = wintypes.HANDLE

        kernel32.ResetEvent.argtypes = [wintypes.HANDLE]
        kernel32.ResetEvent.restype = wintypes.BOOL

        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD

        kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(_OVERLAPPED)]
        kernel32.CancelIoEx.restype = wintypes.BOOL

        hid.HidD_GetAttributes.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_HIDD_ATTRIBUTES)]
        hid.HidD_GetAttributes.restype = wintypes.BOOLEAN

        hid.HidD_GetSerialNumberString.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG]
        hid.HidD_GetSerialNumberString.restype = wintypes.BOOLEAN

        hid.HidD_GetPreparsedData.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
        hid.HidD_GetPreparsedData.restype = wintypes.BOOLEAN

        hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
        hid.HidD_FreePreparsedData.restype = wintypes.BOOLEAN

        hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(_HIDP_CAPS)]
        hid.HidP_GetCaps.restype = ctypes.c_int

        return setupapi, hid, kernel32, cfgmgr32

    _SETUPAPI, _HID, _KERNEL32, _CFGMGR32 = _win_dlls()

    def _win_dev_instance_id(devinst):
        """用 CM_Get_Device_IDW 拿设备实例 ID，如 USB\\VID_046D&PID_C31C\\..."""
        need = wintypes.ULONG(0)
        if _CFGMGR32.CM_Get_Device_ID_Size(ctypes.byref(need), devinst, 0) != 0:
            return None
        if need.value == 0:
            return None
        buf = ctypes.create_unicode_buffer(need.value + 1)
        if _CFGMGR32.CM_Get_Device_IDW(devinst, buf, need.value + 1, 0) != 0:
            return None
        return buf.value

    def _win_bus_of(devinst):
        """走设备树，用第一个祖先的 enumerator 判断总线。

        HID 设备自己的 enumerator 总是 "HID"（它是子设备），总线信息在父设备上：
            USB 设备    -> USB\\VID_...
            蓝牙设备    -> BTHENUM\\{...}
            内置设备    -> ACPI\\...
        """
        cur = devinst
        for _ in range(6):
            parent = wintypes.DWORD(0)
            if _CFGMGR32.CM_Get_Parent(ctypes.byref(parent), cur, 0) != 0:
                break
            iid = _win_dev_instance_id(parent.value)
            if iid:
                enum = iid.split("\\", 1)[0].upper()
                if enum.startswith("BTHENUM"):
                    return "bluetooth"
                if enum.startswith("USB"):
                    return "usb"
                if enum.startswith("ACPI") or enum.startswith("ROOT"):
                    return "bus " + enum.lower()
            cur = parent.value
        return "bus unknown"

    def _win_error(err, msg):
        """把 Windows 错误码变成带 winerror 的异常。

        直接用 OSError(err, ...) 会把 Windows 错误码当成 POSIX errno（错误 32
        在 Windows 是共享冲突，在 POSIX 却是 BrokenPipe），诊断信息会误导。
        ctypes.WinError() 才会给出正确的 .winerror 和异常子类。
        """
        exc = ctypes.WinError(err)
        exc.strerror = "%s（Windows 错误 %d）" % (msg, err)
        return exc

    def _win_open(path, overlapped=False):
        """CreateFileW 打开设备，失败抛异常。

        overlapped=True 时必须传 FILE_FLAG_OVERLAPPED，否则 ReadFile 会同步
        阻塞，WaitForSingleObject 的超时机制根本用不上。
        """
        flags = _FILE_FLAG_OVERLAPPED if overlapped else 0
        h = _KERNEL32.CreateFileW(
            path, _GENERIC_READ | _GENERIC_WRITE,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE, None, _OPEN_EXISTING, flags, None)
        if h == _INVALID_HANDLE_VALUE:
            # _win_error 用 ctypes.WinError，它会按 winerror 映射到正确的
            # 子类（错误 5 -> PermissionError），而不是把 Windows 错误码
            # 当成 POSIX errno。
            raise _win_error(ctypes.get_last_error(),
                             "CreateFileW 失败: %s" % path)
        return h

    def _win_read_attrs(h):
        """读 VID / PID / 序列号，返回 (vid, pid, uniq)。"""
        attrs = _HIDD_ATTRIBUTES()
        attrs.Size = ctypes.sizeof(attrs)
        if not _HID.HidD_GetAttributes(h, ctypes.byref(attrs)):
            return None, None, None
        sn = ctypes.create_unicode_buffer(256)
        uniq = None
        if _HID.HidD_GetSerialNumberString(h, sn, ctypes.sizeof(sn)):
            uniq = sn.value.strip() or None
        return attrs.VendorID, attrs.ProductID, uniq

    def _win_report_len(h):
        """拿设备的输入报告长度（含 report ID）。失败返回 None。"""
        caps = _win_caps(h)
        return (caps.InputReportByteLength or None) if caps else None

    def _win_output_report_len(h):
        """拿设备的输出报告长度（含 report ID）。

        返回 None 表示**能力未知**（查询失败），返回 0 表示**确定不可写**。
        两者不能混为一谈：把未知当成“不可写”会让去重误判唯一性。
        """
        caps = _win_caps(h)
        return caps.OutputReportByteLength if caps else None

    def _win_caps(h):
        """读 HIDP_CAPS。失败返回 None。"""
        pp = ctypes.c_void_p()
        if not _HID.HidD_GetPreparsedData(h, ctypes.byref(pp)):
            return None
        try:
            caps = _HIDP_CAPS()
            if _HID.HidP_GetCaps(pp, ctypes.byref(caps)) != _HIDP_STATUS_SUCCESS:
                return None
            return caps
        finally:
            _HID.HidD_FreePreparsedData(pp)

    def _win_parent_id(devinst):
        """拿父设备的实例 ID。同一个物理设备的多个 HID 接口共享它。"""
        parent = wintypes.DWORD(0)
        if _CFGMGR32.CM_Get_Parent(ctypes.byref(parent), devinst, 0) != 0:
            return None
        return _win_dev_instance_id(parent.value)

    def _win_enumerate():
        """枚举所有 HID 接口，逐个返回 (path, devinst, enumerator)。"""
        hdev = _SETUPAPI.SetupDiGetClassDevsW(
            ctypes.byref(_GUID_DEVINTERFACE_HID), None, None,
            _DIGCF_PRESENT | _DIGCF_DEVICEINTERFACE)
        if hdev == _INVALID_HANDLE_VALUE:
            # 不能当成“没有设备”：那会让 --yes 的歧义判断拿到错误的数量
            raise _win_error(ctypes.get_last_error(), "SetupDiGetClassDevsW 失败")
        try:
            idx = 0
            while True:
                did = _SP_DEVICE_INTERFACE_DATA()
                did.cbSize = ctypes.sizeof(did)
                if not _SETUPAPI.SetupDiEnumDeviceInterfaces(
                        hdev, None, ctypes.byref(_GUID_DEVINTERFACE_HID), idx,
                        ctypes.byref(did)):
                    err = ctypes.get_last_error()
                    if err != _ERROR_NO_MORE_ITEMS:
                        # 枚举真的出错了，不能当成“枚举完了”：否则会静默
                        # 返回不完整列表，而 --yes 的歧义判断依赖这个数量。
                        raise _win_error(err, "SetupDiEnumDeviceInterfaces 失败")
                    return
                idx += 1

                # 两趟调用：先问长度，再拿数据。
                # 第一趟失败是正常的（缓冲区不够），但其它错误不能吞：
                # 静默跳过会让去重误判“只有一个可写接口”而选错设备。
                need = wintypes.DWORD(0)
                ok = _SETUPAPI.SetupDiGetDeviceInterfaceDetailW(
                    hdev, ctypes.byref(did), None, 0, ctypes.byref(need), None)
                if not ok:
                    err = ctypes.get_last_error()
                    if err != _ERROR_INSUFFICIENT_BUFFER or need.value == 0:
                        raise _win_error(
                            err, "SetupDiGetDeviceInterfaceDetailW 取长度失败")

                buf = ctypes.create_string_buffer(need.value)
                # cbSize 字段：32 位是 6，64 位是 8（含 2 字节对齐）
                ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0] = (
                    8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6)
                devinfo = _SP_DEVINFO_DATA()
                devinfo.cbSize = ctypes.sizeof(devinfo)
                if not _SETUPAPI.SetupDiGetDeviceInterfaceDetailW(
                        hdev, ctypes.byref(did), buf, need.value, None,
                        ctypes.byref(devinfo)):
                    raise _win_error(
                        ctypes.get_last_error(),
                        "SetupDiGetDeviceInterfaceDetailW 失败")

                path = ctypes.wstring_at(
                    ctypes.addressof(buf) + ctypes.sizeof(wintypes.DWORD))

                yield path, devinfo.DevInst
        finally:
            _SETUPAPI.SetupDiDestroyDeviceInfoList(hdev)

    def _win_find_devices():
        """枚举 Windows HID 设备，返回 (支持的设备, 跳过的设备)。

        元组格式与 Linux 完全一致：(path, pid, name, bus, uniq)。
        只有 PIDS 里已知的 PID 才进 found。

        一个物理手柄可能暴露多个 HID 接口（键盘常见 4 个），所以按父设备
        去重，优先保留有输出报告的那个。
        """
        candidates = []
        # 打不开或读不到属性的接口：记下它们的父设备，参与歧义判断。
        # 否则一个读不到的兄弟接口会让分组误以为“只剩一个接口”，从而选错目标。
        unresolved = set()
        # 有接口拿不到父设备时置位。此时无法判断任何接口的唯一性，
        # 只能全部拒绝——拿不到父设备就无法知道谁和谁是同一物理设备。
        parent_unknown = False
        for path, devinst in _win_enumerate():
            parent = _win_parent_id(devinst)
            if parent is None:
                parent_unknown = True
                continue
            try:
                h = _win_open(path)
            except OSError:
                unresolved.add(parent)
                continue
            try:
                vid, pid, uniq = _win_read_attrs(h)
                out_len = _win_output_report_len(h)
            finally:
                _KERNEL32.CloseHandle(h)

            if vid is None:
                # 属性读不到：身份未知，算未决。不能当成“不是 Nintendo 设备”
                # 丢掉，否则一个读不到的兄弟接口会让分组误以为唯一。
                unresolved.add(parent)
                continue
            if vid != NINTENDO_VID or pid is None:
                continue

            bus = _win_bus_of(devinst)
            candidates.append((path, pid, bus, uniq, out_len, parent))

        # 按父设备分组，同一个物理设备只留一个接口。
        #
        # 一个手柄可能暴露多个 HID 接口（键盘常见 4 个）。选哪个可写不能猜：
        # 只有恰好一个接口有非零输出报告长度时才确定；多个都非零就是歧义，
        # 这种情况宁可拒绝也不能随便挑一个去写 flash。
        by_parent = {}
        for c in candidates:
            by_parent.setdefault(c[5], []).append(c)

        found, skipped = [], []
        for parent, group in by_parent.items():
            path, pid, bus, uniq, _out, _p = group[0]
            name = PIDS.get(pid, "PID 0x%04X" % pid)

            if parent_unknown:
                # 有接口拿不到父设备：无法确定任何接口的唯一性，全部拒绝
                skipped.append((path, pid,
                                "%s（有接口的父设备无法确定，无法确定唯一性）" % name,
                                bus, uniq))
                continue

            if parent in unresolved:
                # 同一物理设备还有接口读不到，无法确定唯一性
                skipped.append((path, pid,
                                "%s（有兄弟接口读不到，无法确定）" % name,
                                bus, uniq))
                continue

            if len(group) == 1:
                chosen = group[0]   # 只有一个接口，不存在歧义
            else:
                writable = [c for c in group if c[4]]         # 确定可写
                unknown = [c for c in group if c[4] is None]  # 能力未知
                if len(writable) == 1 and not unknown:
                    chosen = writable[0]
                else:
                    # 无法确定该写哪个接口。宁可拒绝，也不能猜一个去写 flash。
                    if len(writable) > 1:
                        why = "%d 个可写接口，无法确定" % len(writable)
                    elif unknown:
                        why = "有接口能力未知，无法确定"
                    else:
                        why = "没有可写接口"
                    skipped.append((path, pid, "%s（%s）" % (name, why), bus, uniq))
                    continue

            path, pid, bus, uniq, _out, _p = chosen
            entry = (path, pid, PIDS.get(pid, "PID 0x%04X" % pid), bus, uniq)
            (found if pid in PIDS else skipped).append(entry)
        return found, skipped

    def _win_still_matches(path, pid, bus, uniq, handle=None):
        """复查设备身份。

        handle 不为 None 时直接查**已经打开、即将用来写入的那个句柄**，
        而不是另开一个句柄——否则真正执行写入的句柄从未被验证过。

        总线通过重新枚举、按路径找回同一个接口来确认：路径没了就说明
        设备已经不在（或已被别的设备顶替），视为身份不明。

        Windows 上 HidD_GetSerialNumberString 常常为空，此时实际只剩
        VID/PID 能比，同型号换机认不出来——调用方会把这个局限告知用户。
        """
        if handle is not None:
            vid, cur_pid, cur_uniq = _win_read_attrs(handle)
        else:
            try:
                h = _win_open(path)
            except OSError:
                return False
            try:
                vid, cur_pid, cur_uniq = _win_read_attrs(h)
            finally:
                _KERNEL32.CloseHandle(h)

        if vid != NINTENDO_VID or cur_pid != pid:
            return False
        # 原来有 uniq、现在读不到了，视为身份不明，不放行
        if uniq and cur_uniq != uniq:
            return False

        # 总线必须重新确认，不能信任枚举时的旧结论
        cur_bus = None
        for p, devinst in _win_enumerate():
            if p == path:
                cur_bus = _win_bus_of(devinst)
                break
        if cur_bus is None or cur_bus != bus:
            return False
        return True

    class _WinTransport:
        """Windows HID 传输层：重叠 I/O 实现带超时的读与写。

        句柄用 FILE_FLAG_OVERLAPPED 打开，所以每一次 I/O 都必须带一个
        **专属且唯一**的 OVERLAPPED 结构（微软文档明确要求，否则 WriteFile
        可能谎报完成）。读和写各用一个，不能共用。

        读操作在超时后保持挂起，下次继续等同一个请求，避免丢数据。
        因此 buf / overlapped / event 在操作真正完成前不能释放或重用——
        包括 close() 路径（CancelIoEx 只是请求取消，不等待完成）。
        """

        def __init__(self, path):
            self.handle = _win_open(path, overlapped=True)
            # 标志先初始化：对象从这一刻起就是自洽的，close() 可安全调用
            self.pending = False
            self.write_pending = False
            self.report_len = _win_report_len(self.handle) or REPORT_LEN
            self.buf = ctypes.create_string_buffer(self.report_len)
            self.overlapped = _OVERLAPPED()
            self.event = _KERNEL32.CreateEventW(None, True, False, None)
            if not self.event:
                # 必须先存错误码：CloseHandle 会覆盖 last error
                err = ctypes.get_last_error()
                _KERNEL32.CloseHandle(self.handle)
                self.handle = None
                raise _win_error(err, "CreateEventW 失败")
            self.overlapped.hEvent = self.event

            # 写用独立的一套，不能和读共用
            self.wbuf = ctypes.create_string_buffer(REPORT_LEN)
            self.woverlapped = _OVERLAPPED()
            self.wevent = _KERNEL32.CreateEventW(None, True, False, None)
            if not self.wevent:
                err = ctypes.get_last_error()
                _KERNEL32.CloseHandle(self.event)
                _KERNEL32.CloseHandle(self.handle)
                self.event = self.handle = None
                raise _win_error(err, "CreateEventW 失败（写）")
            self.woverlapped.hEvent = self.wevent

        # ---- 读 ----

        def _start_read(self):
            """提交读请求。先置 pending 再调用，避免中间被打断时漏记。"""
            if self.pending:
                return
            self.pending = True      # 先置位：ReadFile 一旦提交就是活的
            _KERNEL32.ResetEvent(self.event)
            n = wintypes.DWORD(0)
            ok = _KERNEL32.ReadFile(self.handle, self.buf, self.report_len,
                                    ctypes.byref(n), ctypes.byref(self.overlapped))
            if not ok:
                err = ctypes.get_last_error()
                if err != _ERROR_IO_PENDING:
                    self.pending = False   # 没提交成功，回滚
                    raise _win_error(err, "ReadFile 失败")

        def _collect(self):
            """收已完成的读操作，返回数据。

            只有真正结束的操作才清 pending。ERROR_IO_INCOMPLETE 的含义就是
            “还在进行中”，不能当成结束。
            """
            n = wintypes.DWORD(0)
            if not _KERNEL32.GetOverlappedResult(
                    self.handle, ctypes.byref(self.overlapped),
                    ctypes.byref(n), False):
                err = ctypes.get_last_error()
                if err != _ERROR_IO_INCOMPLETE:
                    self.pending = False
                    raise _win_error(err, "GetOverlappedResult 失败")
                return None   # 还没完成
            self.pending = False
            return self.buf.raw[:n.value]

        def poll(self):
            """非阻塞检查：现在有没有数据可读。"""
            if not self.pending:
                self._start_read()
            return _KERNEL32.WaitForSingleObject(self.event, 0) == _WAIT_OBJECT_0

        def read_nowait(self):
            """非阻塞读，没数据返回 None。"""
            if not self.poll():
                return None
            return self._collect()

        def read(self, timeout):
            """带超时的读，超时返回 None。"""
            if timeout <= 0:
                return None
            self._start_read()
            ms = max(1, int(timeout * 1000))
            rc = _KERNEL32.WaitForSingleObject(self.event, ms)
            if rc == _WAIT_OBJECT_0:
                return self._collect()
            if rc == _WAIT_TIMEOUT:
                return None  # 保持挂起，下次继续等
            # 等待本身失败不代表操作结束，不能清 pending
            raise _win_error(ctypes.get_last_error(), "WaitForSingleObject 失败")

        # ---- 写 ----

        def write(self, buf):
            """写一个报告。

            句柄是重叠模式，所以必须传专属 OVERLAPPED，且 lpNumberOfBytesWritten
            要传 NULL（微软文档：异步时该参数应传 NULL，否则结果可能错误），
            字节数用 GetOverlappedResult 拿。

            等待设了上限：驱动卡死时不能让整个工具挂住，那会连错误报告和
            输入模式恢复都做不了。超时则扣住缓冲区（见 _QUARANTINE）。
            """
            if self.wbuf is None:
                raise OSError("传输已关闭")
            if self.write_pending:
                # 上一次写的完成状态未知，OVERLAPPED 不能重用。
                # 这种情况只能拒绝，不能拿同一个结构再发一次。
                raise OSError("上一次写入尚未确认完成，不能继续发送")

            data = bytes(buf)
            self.wbuf.raw = data + b"\x00" * (REPORT_LEN - len(data))
            _KERNEL32.ResetEvent(self.wevent)
            # 提交前置位：一旦 WriteFile 返回，操作就是活的，
            # 中途被 Ctrl-C 打断也不会漏记（否则恢复流程会重用这个 OVERLAPPED）。
            self.write_pending = True
            ok = _KERNEL32.WriteFile(self.handle, self.wbuf, len(data),
                                     None, ctypes.byref(self.woverlapped))
            if not ok:
                err = ctypes.get_last_error()
                if err != _ERROR_IO_PENDING:
                    self.write_pending = False   # 没提交成功，回滚
                    raise _win_error(err, "WriteFile 失败")

            rc = _KERNEL32.WaitForSingleObject(self.wevent, _WRITE_WAIT_MS)
            if rc != _WAIT_OBJECT_0:
                # 完成状态未知。内核可能还在写 wbuf/woverlapped，绝不能释放，
                # 也不能重用。整个对象交给 _QUARANTINE 扣住（一次 append，
                # 没有可被打断的中间状态）。
                # write_pending 保持 True：后续写入必须继续被拒绝，
                # 否则会重用这个未决的 OVERLAPPED。
                if self not in _QUARANTINE:
                    _QUARANTINE.append(self)
                if rc == _WAIT_TIMEOUT:
                    raise OSError(
                        "写入未在 %d ms 内完成（命令是否送达未知）" % _WRITE_WAIT_MS)
                raise _win_error(ctypes.get_last_error(), "等待写入完成失败")

            self.write_pending = False
            n = wintypes.DWORD(0)
            if not _KERNEL32.GetOverlappedResult(
                    self.handle, ctypes.byref(self.woverlapped),
                    ctypes.byref(n), False):
                raise _win_error(ctypes.get_last_error(), "写入未完成")
            if n.value != len(data):
                raise OSError("短写：只发出 %d / %d 字节" % (n.value, len(data)))

        def identity(self):
            """返回**已打开的原生句柄**，供写入前复查身份用。

            返回句柄而不是属性：调用方要验证的正是即将用来写入的那个句柄，
            由复查函数自己去读它的属性。Linux 后端返回 None。
            """
            return self.handle

        def close(self):
            """关闭。

            CancelIoEx 只是“请求”取消，不等待完成；在操作真正结束前释放
            OVERLAPPED / buf 是原生内存违规。所以取消后要等它结束。

            等待设了上限。超时**不能**释放资源（内核可能还在用），而是把
            buf/overlapped/event 交给 _QUARANTINE 扣住不放。这是刻意的：
            泄漏几个缓冲区好过内核写已释放的内存。

            pending / write_pending 只在确认结束后才清：若本方法自己被打断，
            标志仍为真，资源仍归本对象所有，下次 close() 会重新处理。
            """
            pending = getattr(self, "pending", False)
            write_pending = getattr(self, "write_pending", False)
            handle = getattr(self, "handle", None)
            event = getattr(self, "event", None)
            wevent = getattr(self, "wevent", None)

            if pending or write_pending:
                # 先扣住，再做任何事：从这一刻起，无论后面哪一步被打断，
                # 资源都不会被释放。确认结束后再移出。
                # 先查重：重复扣留只是记账泄漏，但没必要留。
                if self not in _QUARANTINE:
                    _QUARANTINE.append(self)

                if pending:
                    _KERNEL32.CancelIoEx(handle, ctypes.byref(self.overlapped))
                    if _KERNEL32.WaitForSingleObject(
                            event, _CLOSE_WAIT_MS) == _WAIT_OBJECT_0:
                        self.pending = False
                        n = wintypes.DWORD(0)
                        # 已信号，收尾即可（正常完成/已取消/出错都算结束）
                        _KERNEL32.GetOverlappedResult(
                            handle, ctypes.byref(self.overlapped),
                            ctypes.byref(n), False)
                    else:
                        return   # 未确认完成，保持扣住

                if write_pending:
                    # 写的完成状态未知，保持扣住
                    _KERNEL32.CancelIoEx(handle, ctypes.byref(self.woverlapped))
                    return

                # 读和写都确认结束了，可以安全释放
                while self in _QUARANTINE:
                    _QUARANTINE.remove(self)

            for ev in (event, wevent):
                if ev:
                    _KERNEL32.CloseHandle(ev)
            self.event = self.wevent = None
            self.buf = self.wbuf = self.overlapped = self.woverlapped = None
            if handle:
                _KERNEL32.CloseHandle(handle)
                self.handle = None


class _LinuxTransport:
    """Linux HID 传输层：/dev/hidraw 文件描述符 + select。"""

    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR)

    def poll(self):
        return bool(select.select([self.fd], [], [], 0)[0])

    def read_nowait(self):
        return os.read(self.fd, REPORT_LEN)

    def read(self, timeout):
        if timeout <= 0:
            return None
        if not select.select([self.fd], [], [], timeout)[0]:
            return None
        return os.read(self.fd, REPORT_LEN)

    def write(self, buf):
        n = os.write(self.fd, bytes(buf))
        if n != len(buf):
            raise OSError("短写：只发出 %d / %d 字节" % (n, len(buf)))

    def identity(self):
        """Linux 后端没有句柄级属性查询，返回 None。

        main() 会退回用路径重新读 sysfs 的方式复查身份（见 still_matches）。
        """
        return None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def hexs(data):
    return " ".join("%02X" % b for b in data)


def short_path(path):
    """缩短设备路径，仅用于显示。

    Windows 的 HID 接口路径很长（带一长串 GUID），会把输出格式撑破。
    内部仍用完整路径打开设备，这里只影响打印。
    """
    if IS_WINDOWS and "#{" in path:
        return path.split("#{", 1)[0]
    return path


def read_hid_info(syspath):
    """读 /sys/class/hidraw/hidrawN/device/uevent。

    返回 (bus_hex, vid, pid, uniq)，读不到返回 None。

    uniq 是设备唯一标识，蓝牙手柄上是手柄自己的 BD 地址，用来区分同型号的
    不同手柄。内核只把它放在 uevent 的 HID_UNIQ= 行里，没有独立的 sysfs
    文件（见 drivers/hid/hid-core.c 的 hid_uevent），而且可能为空。
    """
    try:
        with open(os.path.join(syspath, "device", "uevent")) as f:
            uevent = f.read()
    except OSError:
        return None

    bus_hex = vid = pid = None
    uniq = None
    for line in uevent.splitlines():
        if line.startswith("HID_ID="):
            # HID_ID=0005:0000057E:00002006  ->  bus:vid:pid
            try:
                bus_hex, vid_hex, pid_hex = line.split("=", 1)[1].strip().split(":")
                vid, pid = int(vid_hex, 16), int(pid_hex, 16)
            except ValueError:
                return None
        elif line.startswith("HID_UNIQ="):
            uniq = line.split("=", 1)[1].strip() or None
    if vid is None:
        return None
    return bus_hex, vid, pid, uniq


def describe(syspath):
    """把一个 hidraw sysfs 节点解成 (path, pid, name, bus, uniq)，不是 Nintendo 设备返回 None。"""
    info = read_hid_info(syspath)
    if info is None:
        return None
    bus_hex, vid, pid, uniq = info
    if vid != NINTENDO_VID:
        return None
    return ("/dev/" + os.path.basename(syspath), pid,
            PIDS.get(pid, "PID 0x%04X" % pid),
            BUS_NAMES.get(bus_hex, "bus " + bus_hex),
            uniq)


def find_devices():
    """枚举 HID 设备，返回 (支持的设备, 跳过的设备)。

    元组格式两边一致：(path, pid, name, bus, uniq)。
    只接受 PIDS 里已知的手柄。未知 PID 一律跳过：本脚本会写 SPI flash，
    不能对没确认过协议的设备下手。
    """
    if IS_WINDOWS:
        return _win_find_devices()

    found, skipped = [], []
    for syspath in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        dev = describe(syspath)
        if dev is None:
            continue
        (found if dev[1] in PIDS else skipped).append(dev)
    return found, skipped


def still_matches(path, pid, bus, uniq, handle=None):
    """复查设备身份。

    设备节点会在枚举到打开之间被复用：如果手柄断开、别的设备占了同一个节点，
    光看路径就会把命令发给错误的设备。写 flash 前必须再确认一次。

    handle 不为 None 时（Windows 传的是**已打开的原生句柄**），直接查那个
    即将用于写入的句柄，而不是另开一个——否则真正执行写入的句柄从未被验证过。

    PID/总线只能挡住换了型号的情况。同型号换机要靠 uniq（手柄的蓝牙地址）。
    原来有 uniq、现在读不到了，视为身份不明，不放行。
    """
    if IS_WINDOWS:
        return _win_still_matches(path, pid, bus, uniq, handle)

    dev = describe("/sys/class/hidraw/" + os.path.basename(path))
    if dev is None or dev[1] != pid or dev[3] != bus:
        return False
    if uniq and dev[4] != uniq:
        return False
    return True


def pairing_cleared(dev):
    """回读 SPI 配对槽的魔数，返回 (是否已清除, 原因)。

    0x07 的文档描述是「初始化 0x2000 SPI 段」，所以槽首魔数应不再是 0x95
    （有效配对记录）。这是直接证据，不像 0x05 那样依赖未证实的内存态语义。

    配对记录按 0x26 字节重复，槽数不定。槽 1 是当前配对；槽 1 为 0x00 时
    文档说它是上一个配对、槽 2 才是当前配对。所以抽查前两个槽就覆盖了文档
    描述的这两种情况。更靠后的记录抽查不到——这是已知局限，输出里会说明。
    """
    for i in range(PAIRING_SLOTS):
        addr = SPI_PAIRING + i * PAIRING_SLOT
        data = dev.spi_read(addr, 1)
        if data is None:
            return False, "读不到 SPI 0x%04X" % addr
        if data[0] == PAIRING_MAGIC:
            return False, "SPI 0x%04X 仍是有效配对记录（魔数 0x95）" % addr
    return True, ""


def page_list_state(dev):
    """查 0x05 主机列表状态，返回数据字节（读不到返回 None）。只作参考，不当门禁。

    文档只说 0x07「初始化 0x2000 SPI 段」，是否同时清掉手柄内存里的主机列表
    没有任何文档或驱动实现能证实。拿它当门禁会在真机上造成假中止，所以只打印。
    """
    ok, rep = dev.subcmd(SUB_PAGE_LIST)
    if not ok or rep is None or len(rep) < 16:
        return None
    return rep[15]


def abort(hint, ops=()):
    """打印中止说明并返回退出码 1。

    不断言手柄还能用：中止时它可能还停在 0x3F，能不能用取决于恢复是否
    成功，那个结果由 finally 块打印。
    """
    print()
    print("已中止，未发送断电命令。%s" % hint)
    report_state(ops)
    return 1


def report_state(ops):
    """如实报告手柄可能处于什么状态。

    ops 是 [(描述, 状态)]，状态为 "进行中" / "已确认" / "未确认" / "已发出"。
    "已确认" 只代表命令收到了回复，不代表回读校验通过。
    "进行中" 表示命令可能已经发出去了，只是没等到回复。
    """
    acked = [d for d, s in ops if s == "已确认"]
    unsure = [d for d, s in ops if s in ("进行中", "未确认")]
    sent = [d for d, s in ops if s == "已发出"]
    if acked:
        print("  已确认收到回复：%s" % "、".join(acked))
    if unsure:
        print("  可能已发出、未确认：%s" % "、".join(unsure))
    if sent:
        print("  已发出（无回复）：%s" % "、".join(sent))
    if ops:
        print("  手柄可能处于中间状态，请重连后重跑本脚本。")


class Device:
    def __init__(self, path, dry=False):
        self.dry = dry
        self.seq = 0
        self._t = None      # 先置空：传输层构造失败时 close() 仍可安全调用
        if dry:
            return
        if IS_WINDOWS:
            self._t = _WinTransport(path)
        else:
            self._t = _LinuxTransport(path)

    def close(self):
        if self._t is not None:
            self._t.close()
            self._t = None

    def identity(self):
        """返回当前已打开的原生句柄（Windows）或 None（Linux）。

        用于写入前复查：查的必须是即将用来写入的那个句柄，而不是另开一个。
        Linux 后端没有句柄级属性查询，返回 None，由 still_matches 走 sysfs。
        """
        if self._t is None:
            return None
        return self._t.identity()

    def drain(self):
        """丢弃积压的输入报告，避免读到旧数据。

        设上限，避免描述符一直可读时死循环。
        """
        if self.dry:
            return
        for _ in range(DRAIN_MAX):
            if not self._t.poll():
                return
            self._t.read_nowait()

    def _write(self, subcmd, data):
        buf = bytearray(REPORT_LEN)
        buf[0] = 0x01
        buf[1] = self.seq & 0x0F
        self.seq += 1
        buf[2:10] = RUMBLE
        buf[10] = subcmd
        buf[11:11 + len(data)] = data

        if self.dry:
            print("      > " + hexs(buf[:11 + len(data)]))
            return
        self._t.write(buf)

    def _read_report(self, timeout):
        if timeout <= 0:
            return None
        return self._t.read(timeout)

    def subcmd(self, subcmd, data=b"", timeout=2.0, ack=(ACK_OK,), match=None):
        """发子命令并等它的 0x21 回复，返回 (ok, reply)。

        ok=True 表示收到了子命令回显正确、且确认字节在 ack 里的回复。
        ack=None 表示不校验确认字节，用于非破坏性的 0x03 / 0x30。
        match 是一个可选谓词，返回 False 的回复会被跳过并继续等，
        用于把迟到的、属于其它请求的回复排除掉。
        发 0x06 00 时手柄立刻断电、不会有回复，直接返回 (True, None)。
        """
        self.drain()  # 先清积压，减少旧回复被误认成当前回复的机会
        self._write(subcmd, data)
        if self.dry:
            return True, None
        time.sleep(0.1)  # 手柄处理不过来太快

        # 关机命令发完手柄就断电了，不会有回复
        if subcmd == SUB_HCI_STATE and (not data or data[0] == 0x00):
            return True, None

        deadline = time.time() + timeout
        while True:
            rep = self._read_report(deadline - time.time())
            if rep is None:
                return False, None
            # 跳过普通状态报告 0x30，只认子命令回复 0x21
            if len(rep) >= 15 and rep[0] == 0x21 and rep[14] == subcmd:
                if match is not None and not match(rep):
                    continue  # 不是我们要的那次回复，继续等
                if ack is not None and rep[13] not in ack:
                    return False, rep  # 收到回复但确认字节不对
                return True, rep

    def restore_input_mode(self):
        """把输入模式切回标准全模式 0x30，返回是否确认成功。

        0x3F（Simple HID）只在按键变化时上报，而 Linux hid-nintendo 的
        read_handler 只处理 0x21 / 0x30 / 0x31，不认 0x3F：手柄会看着还连着，
        但按键全部失灵。所以任何非成功退出都必须切回 0x30。
        """
        if self.dry:
            return True
        try:
            ok, _ = self.subcmd(SUB_INPUT_MODE, bytes([0x30]), timeout=1.0)
            return ok
        except OSError:
            return False

    def spi_read(self, addr, size):
        """子命令 0x10 读 SPI flash，返回 size 字节，失败返回 None。

        同时校验确认字节、回显地址和返回长度。地址/长度不符的回复会被
        跳过并继续等（可能是上一个请求迟到的回复），而不是直接判失败。
        """
        if size > SPI_READ_MAX:
            raise ValueError("单次 SPI 读取最多 %d 字节" % SPI_READ_MAX)

        def matches(rep):
            return (len(rep) >= 20 + size
                    and struct.unpack("<I", rep[15:19])[0] == addr
                    and rep[19] == size)

        ok, rep = self.subcmd(SUB_SPI_READ,
                              struct.pack("<I", addr) + bytes([size]),
                              ack=(ACK_SPI_READ,), match=matches)
        if self.dry:
            # dry-run 用假数据让流程走完，好把后续要发的包都预览出来
            return bytes(size)
        if not ok or rep is None:
            return None
        return bytes(rep[20:20 + size])

def pick_device(devices, assume_yes):
    if len(devices) == 1:
        return devices[0]

    print("检测到多个 Nintendo 手柄：")
    for i, (path, pid, name, bus, uniq) in enumerate(devices, 1):
        print("  [%d] %-22s %s  (%s)" % (i, name, short_path(path), bus))

    if assume_yes:
        sys.exit("有多个手柄，--yes 模式下无法自动选择，请先只连一个。")

    while True:
        s = input("选择要关闭的手柄 [1-%d]: " % len(devices)).strip()
        if s.isdigit() and 1 <= int(s) <= len(devices):
            return devices[int(s) - 1]


def main():
    ap = argparse.ArgumentParser(
        description="把 Nintendo Switch 手柄关到出厂态（Linux / Windows）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="警告：本脚本会写手柄的 SPI flash（0x2000 段）。用错可能变砖，自负风险。",
    )
    ap.add_argument("-l", "--list", action="store_true", help="只列出检测到的手柄")
    ap.add_argument("-y", "--yes", action="store_true", help="跳过所有交互确认")
    ap.add_argument("-n", "--dry-run", action="store_true", help="只打印要发的字节，不实际操作")
    args = ap.parse_args()

    devices, skipped = find_devices()
    if not devices:
        if skipped:
            sys.exit("找到 %d 个 Nintendo 设备，但 PID 都不在支持列表里：\n%s\n"
                     "本脚本会写 SPI flash，不支持未验证协议的设备。"
                     % (len(skipped), "\n".join(
                         "  %s  %s  (%s)" % (name, path, bus)
                         for path, pid, name, bus, uniq in skipped)))
        sys.exit("没找到 Nintendo 手柄。请先用蓝牙配对并连接，再重试。")

    if args.list:
        for path, pid, name, bus, uniq in devices:
            print("%-22s %s  (%s)" % (name, short_path(path), bus))
        for path, pid, name, bus, uniq in skipped:
            print("%-22s %s  (%s)  [不支持]" % (name, short_path(path), bus))
        return 0

    path, pid, name, bus, uniq = pick_device(devices, args.yes)
    print("\n目标：%s  (%s, %s)" % (name, short_path(path), bus))

    if bus != "bluetooth":
        print()
        print("✗ 这不是蓝牙连接（%s）。" % bus)
        print("  0x06 在 USB 下不生效，手柄不会立即断电；")
        print("  0x08 的「断开时进 HID OFF」也不会触发。")
        print()
        print("  这里不给绕过选项：继续下去只会不可逆地清掉配对信息、")
        print("  写掉低功耗标志，却跳过唯一能让标志生效的那一步，")
        print("  结果比什么都不做更糟。")
        print()
        print("  请改用蓝牙连接后重试。")
        return 1

    if not args.dry_run and not args.yes:
        print()
        print("本脚本会向手柄 SPI flash 写入，把它恢复到出厂装运态：")
        print("  - 清除配对信息（0x2000 段）")
        print("  - 置低功耗标志（0x5000 段）")
        print("  - 立即断电")
        print()
        print("唤醒方式：插 USB 到 Switch，或长按 sync 键重新配对。")
        print()
        if input("继续？(y/N): ").strip().lower() != "y":
            return 1

    try:
        dev = Device(path, dry=args.dry_run)
    except PermissionError:
        sys.exit("没有权限打开 %s。请用 sudo 运行，或把用户加入相应的设备组。" % path)
    except OSError as e:
        sys.exit("打不开 %s：%s\n手柄可能在枚举后断开了，请重连后重试。" % (path, e))

    # 设备节点会被复用，写 flash 前复查一次身份。
    # Windows 上把已打开的原生句柄传进去，查的就是即将用来写入的那一个。
    #
    # 这一步放在 try 块里（见下）：复查过程会重新枚举设备，枚举失败会抛异常，
    # 必须保证 dev 被关掉，不能把句柄漏出去。
    def verify_identity():
        if args.dry_run or still_matches(path, pid, bus, uniq, dev.identity()):
            return True
        print("✗ %s 已经不是刚才枚举到的手柄了"
              "（可能断开后被别的设备占用了编号）。" % short_path(path))
        print("  请重连手柄后重试。")
        return False

    ops = []        # [(描述, 状态)]，只在真跑时记录。状态见 report_state
    needs_restore = False   # 切到 0x3F 之后，任何非成功退出都要切回 0x30

    def track(desc, state=None):
        """记录破坏性操作的状态。

        用 ops[-1] 原地改状态，而不是分开维护 done/pending：后者在两条赋值
        之间被 Ctrl-C 打断时，会漏报或重报一个已经发出去的命令。
        dry-run 不记录：什么都没发，报“已确认”会骗人。
        """
        if args.dry_run:
            return
        if state is None:
            ops.append((desc, "进行中"))
        else:
            ops[-1] = (desc, state)

    try:
        if not verify_identity():
            return 1
        if not args.dry_run and not uniq:
            print("注：这台设备没暴露唯一标识（手柄蓝牙地址/序列号），"
                  "只能靠 PID/总线确认身份，同型号换机会认不出来。")
        print("\n[1/6] 切 Simple HID 输入模式")
        # 先置位：即使这条写失败，手柄也可能已经切过去了。
        # 多恢复一次无害（0x30 本来就是正常模式），漏恢复才会按键失灵。
        needs_restore = True
        dev.subcmd(SUB_INPUT_MODE, bytes([0x3F]), ack=None)

        print("[2/6] 点亮 4 个灯")
        dev.subcmd(SUB_LEDS, bytes([0xF0]), ack=None)
        if not args.yes and not args.dry_run:
            print("      请确认手柄上 4 个灯同时在闪。")
            print("      如果不是 4 个灯同时闪，说明不是蓝牙连接，请立刻取消。")
            if input("      4 个灯同时在闪吗？(y/N): ").strip().lower() != "y":
                dev.subcmd(SUB_LEDS, bytes([0x01]), ack=None)  # 恢复 1 号灯
                print("已取消，未执行 flash 写入。")
                return 1

        print("[3/6] 清配对信息 (SPI 0x2000)")
        track("清配对信息 (0x07)")
        ok, _ = dev.subcmd(SUB_RESET_PAIR)
        track("清配对信息 (0x07)", "已确认" if ok else "未确认")
        if not ok:
            print("      ✗ 没收到正确确认，配对信息可能没被清除。")
            return abort("请重试。", ops)

        print("[4/6] 置装运低功耗标志 (SPI 0x5000 = 0x01)")
        track("置装运标志 (0x08)")
        ok, _ = dev.subcmd(SUB_SHIPMENT, bytes([0x01]))
        track("置装运标志 (0x08)", "已确认" if ok else "未确认")
        if not ok:
            print("      ✗ 没收到正确确认，装运标志可能没写进去。")
            return abort("请重试。", ops)

        print("[5/6] 回读校验")
        # dry-run 也走一遍，把要发的包打出来，只是不校验结果
        flag = dev.spi_read(SPI_SHIPMENT, 1)
        cleared, why = pairing_cleared(dev)
        state = page_list_state(dev)
        if args.dry_run:
            print("      (dry-run，不校验)")
        else:
            if flag != b"\x01":
                print("      ✗ SPI 0x5000 = %s，不是 0x01。"
                      % (hexs(flag) if flag else "读不到"))
                print("      无法确认装运低功耗标志已写入。")
                return abort("请重试。", ops)
            print("      SPI 0x5000 = 0x01  ✓")

            if not cleared:
                print("      ✗ %s。" % why)
                print("      配对信息没确认清除，手柄仍可能被按键唤醒。")
                return abort("请重试。", ops)
            print("      SPI 0x2000 前 %d 个配对槽已清除  ✓" % PAIRING_SLOTS)
            print("      （只抽查了前 %d 个槽，更靠后的记录没检查）" % PAIRING_SLOTS)

        if state is not None:
            print("      0x05 主机列表状态 = 0x%02X（参考值，不作判据）" % state)

        # 非蓝牙连接在进入本流程之前就已经拒绝了（见 main 开头的总线检查），
        # 所以这里不需要再判一次。
        print("[6/6] 断开并断电")
        track("断电命令 (0x06)")
        dev.subcmd(SUB_HCI_STATE, bytes([0x00]), ack=None)
        # 0x06 没有回复（手柄直接断电），只能记成"已发出"。
        track("断电命令 (0x06)", "已发出")
        # 手柄会断电，不需要恢复输入模式。
        # 放在写之后：若上面抛异常（命令没发出去），仍然会恢复。
        needs_restore = False

        print()
        if args.dry_run:
            print("dry-run 结束，什么都没发。")
        else:
            print("完成，手柄应已断电。")
            print("唤醒：插 USB 到 Switch，或长按 sync 键重新配对。")
        return 0
    except OSError as e:
        print()
        print("✗ 操作中断：%s" % e)
        print("  手柄可能在过程中断开了。")
        report_state(ops)
        return 1
    except (KeyboardInterrupt, EOFError):
        print()
        if ops:
            print("已中断。")
            report_state(ops)
        elif args.dry_run:
            print("已中断，未做任何修改。")
        else:
            # 此时可能已经发过 0x03 3F / 0x30 F0（灯会变），但没碰 flash
            print("已中断，未执行 flash 写入或断电操作。")
        return 1
    finally:
        # 恢复和它的提示输出都必须包在 try 里：输出可能抛异常
        # （比如管道被对端关掉时的 BrokenPipeError），那不能阻止 dev.close()。
        # 否则一个未决的 I/O 会连同缓冲区一起被释放。
        try:
            if needs_restore and not args.dry_run:
                try:
                    if dev.restore_input_mode():
                        print("已把手柄恢复成标准输入模式。")
                    else:
                        print("⚠ 未能确认手柄已恢复标准输入模式。")
                        print("  请断开重连手柄，否则按键可能失灵。")
                except (KeyboardInterrupt, EOFError):
                    print()
                    print("⚠ 恢复过程被中断，请断开重连手柄，否则按键可能失灵。")
        finally:
            dev.close()


if __name__ == "__main__":
    # 用 os._exit 而不是 sys.exit：后者会走解释器清理，先清模块全局变量，
    # 可能把 _QUARANTINE 里那些“内核可能还在写”的缓冲区释放掉。
    # 跳过清理、直接结束进程，由系统回收一切，才是安全的。
    #
    # 必须用 try/finally 包住：main() 自己抛异常（比如恢复阶段被 Ctrl-C）
    # 时，如果直接冒出去，就会走正常的解释器清理，_QUARANTINE 白做了。
    _rc = 1
    try:
        _rc = main()
    except SystemExit as _e:
        # argparse（--help / 参数错误）和 sys.exit() 的正常退出路径。
        # 必须保留它们的退出码：--help 是 0，参数错误是 2。
        if isinstance(_e.code, int):
            _rc = _e.code
        elif _e.code is None:
            _rc = 0
        else:
            # sys.exit("message")：Python 正常会把消息打到 stderr，
            # 因为这里绕过了正常退出流程，得自己补上，否则错误说明会丢。
            # 用 str() 而不是 "%s" %：后者会把元组当成格式化参数。
            _rc = 1
            try:
                sys.stderr.write(str(_e.code) + "\n")
            except BaseException:
                pass
    except BaseException as _e:
        try:
            sys.stderr.write("✗ 未预期的错误：%s: %s\n" % (type(_e).__name__, _e))
        except BaseException:
            pass
    finally:
        # 每个流单独保护，且捕获 BaseException：任何 flush 失败都不能
        # 阻止 os._exit 执行（否则又回到解释器清理那条路）。
        for _s in (sys.stdout, sys.stderr):
            try:
                _s.flush()
            except BaseException:
                pass
        # os._exit 对超出 C int 范围的值会抛 OverflowError，夹一下
        if not isinstance(_rc, int) or not (0 <= _rc <= 255):
            _rc = 1
        os._exit(_rc)
