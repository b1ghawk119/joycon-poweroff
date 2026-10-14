#!/usr/bin/env python3
"""joycon-poweroff 的自动化测试套件。

用假的 os/select 在内存里模拟 hidraw 设备，不需要真实手柄。覆盖：

  - 协议字节序列（子命令、包序号、64 字节长度、震动字段）
  - 设备发现与身份校验（PID 白名单、总线识别、同型号换机）
  - 每一步的校验门（ACK 字节、SPI 回显地址与返回长度）
  - 所有失败分支都不会发送断电命令
  - 所有非成功退出路径都会恢复标准输入模式
  - dry-run、USB 拒绝、Ctrl-C / EOF 中断、中途断开

运行：

    python3 test_joycon_poweroff.py

全部通过时退出码为 0，否则为 1。
"""
import builtins
import importlib.util
import os
import struct
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "joycon-poweroff.py")
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  %s %s%s" % ("✓" if cond else "✗", name, ("  — " + str(detail)) if detail else ""))


def load():
    spec = importlib.util.spec_from_file_location("m", SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def reply(subcmd, ack=0x80, addr=0, size=0, data=b"", payload=None):
    """构造 0x21 子命令回复。payload 放在偏移 15（回复数据起点）。"""
    r = bytearray(64)
    r[0], r[13], r[14] = 0x21, ack, subcmd
    r[15:19] = struct.pack("<I", addr)
    r[19] = size
    r[20:20 + len(data)] = data
    if payload is not None:
        r[15:15 + len(payload)] = payload
    return bytes(r)


def spi_reply(addr, size, data, ack=0x90):
    return reply(0x10, ack=ack, addr=addr, size=size, data=data)


def happy_replies(page_list=0x00, pairing=(0xFF, 0xFF)):
    """正常流程回复序列：03,30,07,08,10(0x5000),10(0x2000),10(0x2026),05"""
    return [
        reply(0x03), reply(0x30), reply(0x07), reply(0x08),
        spi_reply(0x5000, 1, b"\x01"),
        spi_reply(0x2000, 1, bytes([pairing[0]])),
        spi_reply(0x2026, 1, bytes([pairing[1]])),
        reply(0x05, payload=bytes([page_list])),
    ]


def harness(replies=None, argv=None, write_fail_at=None, read_fail_at=None,
            write_raises=False, read_raises=False):
    m = load()
    writes, box = [], list(replies or [])
    state = {"w": 0, "r": 0}

    class FakeOS:
        O_RDWR = os.O_RDWR
        path = os.path
        @staticmethod
        def open(p, f): return 42
        @staticmethod
        def close(fd): pass
        @staticmethod
        def write(fd, d):
            state["w"] += 1
            if write_raises or state["w"] == write_fail_at:
                raise OSError(19, "No such device")
            writes.append(bytes(d))
            return len(d)
        @staticmethod
        def read(fd, n):
            state["r"] += 1
            if read_raises or state["r"] == read_fail_at:
                raise OSError(19, "No such device")
            if not box:
                raise OSError(19, "No such device")
            return box.pop(0)

    class FakeSelect:
        @staticmethod
        def select(r, w, x, t): return (r, [], []) if box else ([], [], [])

    m.os, m.select = FakeOS, FakeSelect
    m.time.sleep = lambda s: None
    m.Device.drain = lambda self: None
    m.still_matches = lambda *a: True
    m.find_devices = lambda: ([("/dev/hidraw3", 0x2007, "Joy-Con (R)", "bluetooth", None)], [])
    sys.argv = argv or ["x", "--yes"]
    return m, writes, box


def subcmds(writes):
    return ["0x%02X" % w[10] for w in writes]


def restored(writes):
    return any(w[10] == 0x03 and w[11] == 0x30 for w in writes)


print("### #1 未知 PID 必须被拒绝")
m = load()
m.glob.glob = lambda pat: ["/sys/class/hidraw/hidraw3"]
m.read_hid_info = lambda p: ("0005", 0x057E, 0x9999, None)
found, skipped = m.find_devices()
check("未知 PID 不进 found", found == [] and len(skipped) == 1)
m.read_hid_info = lambda p: ("0005", 0x057E, 0x2007, None)
found, _ = m.find_devices()
check("已知 PID 正常进 found", len(found) == 1 and found[0][1] == 0x2007)

m, writes, _ = harness(argv=["x", "--yes"])
m.find_devices = lambda: ([], [("/dev/hidraw9", 0x9999, "PID 0x9999", "bluetooth", None)])
try:
    m.main(); check("无支持设备时报错退出", False)
except SystemExit as e:
    check("无支持设备时报错退出", "PID 都不在支持列表" in str(e))

print("\n### #11 uniq 必须从 uevent 的 HID_UNIQ= 解析（内核没有独立 uniq 文件）")
m = load()
UEVENT = ("DRIVER=hid-generic\n"
          "HID_ID=0005:0000057E:00002007\n"
          "HID_NAME=Nintendo Switch Joy-Con (R)\n"
          "HID_PHYS=aa:bb:cc:dd:ee:ff\n"
          "HID_UNIQ=11:22:33:44:55:66\n")
import builtins as _b
real_open = _b.open
_b.open = lambda p, *a, **k: __import__("io").StringIO(UEVENT) if "uevent" in str(p) else real_open(p, *a, **k)
info = m.read_hid_info("/sys/class/hidraw/hidraw3")
_b.open = real_open
check("HID_UNIQ 被解析出来", info == ("0005", 0x057E, 0x2007, "11:22:33:44:55:66"), info)
check("read_uniq 已不存在（不再读不存在的文件）", not hasattr(m, "read_uniq"))

m = load()
_b.open = lambda p, *a, **k: __import__("io").StringIO("HID_ID=0005:0000057E:00002007\n") if "uevent" in str(p) else real_open(p, *a, **k)
info = m.read_hid_info("/sys/class/hidraw/hidraw3")
_b.open = real_open
check("无 HID_UNIQ 时 uniq 为 None", info == ("0005", 0x057E, 0x2007, None), info)

print("\n### #2 + #7 设备身份复查（含同型号换机，失败关闭）")
m = load()
m.read_hid_info = lambda p: ("0005", 0x057E, 0x2007, "aa:bb:cc:dd:ee:ff")
check("身份+uniq 一致 -> True", m.still_matches("/dev/hidraw3", 0x2007, "bluetooth", "aa:bb:cc:dd:ee:ff"))
m.read_hid_info = lambda p: ("0005", 0x057E, 0x2009, "aa:bb:cc:dd:ee:ff")
check("PID 变了 -> False", not m.still_matches("/dev/hidraw3", 0x2007, "bluetooth", None))
m.read_hid_info = lambda p: ("0003", 0x057E, 0x2007, "aa:bb:cc:dd:ee:ff")
check("总线变了 -> False", not m.still_matches("/dev/hidraw3", 0x2007, "bluetooth", None))
m.read_hid_info = lambda p: ("0005", 0x057E, 0x2007, "11:22:33:44:55:66")
check("#7 同型号换机（uniq 不同）-> False",
      not m.still_matches("/dev/hidraw3", 0x2007, "bluetooth", "aa:bb:cc:dd:ee:ff"))
m.read_hid_info = lambda p: ("0005", 0x057E, 0x2007, None)
check("#11 原来有 uniq、现在读不到 -> False（失败关闭）",
      not m.still_matches("/dev/hidraw3", 0x2007, "bluetooth", "aa:bb:cc:dd:ee:ff"))
m.read_hid_info = lambda p: ("0005", 0x057E, 0x2007, "aa:bb:cc:dd:ee:ff")
check("原来无 uniq 时退回 PID/总线 -> True",
      m.still_matches("/dev/hidraw3", 0x2007, "bluetooth", None))
m.read_hid_info = lambda p: None
check("设备消失 -> False", not m.still_matches("/dev/hidraw3", 0x2007, "bluetooth", None))

print("\n### #3 校验失败必须中止，不发 0x06")
m, writes, _ = harness(replies=[])
rc = m.main()
check("全部无回复 -> 不发 0x06", "0x06" not in subcmds(writes), subcmds(writes))
check("全部无回复 -> 退出码 1", rc == 1)

m, writes, _ = harness(replies=happy_replies()[:3])
m.main()
check("0x08 无确认 -> 不发 0x06", "0x06" not in subcmds(writes), subcmds(writes))

m, writes, _ = harness(replies=happy_replies()[:4])
m.main()
check("回读失败 -> 不发 0x06", "0x06" not in subcmds(writes), subcmds(writes))

m, writes, _ = harness(replies=happy_replies()[:3] + [reply(0x08, ack=0x00)])
m.main()
check("0x08 收到 NAK -> 不发 0x06", "0x06" not in subcmds(writes))

print("\n### #4 + #10 + #16 spi_read 校验与迟到回复")
for label, reps, want in [
    ("正确回复", [spi_reply(0x5000, 1, b"\x01")], True),
    ("回显地址错误后无更多数据", [spi_reply(0x9999, 1, b"\x01")], False),
    ("ACK 是 0x00", [spi_reply(0x5000, 1, b"\x01", ack=0x00)], False),
    ("返回长度不符", [spi_reply(0x5000, 16, b"\x01" * 16)], False),
    ("#10 迟到旧回复+正确回复", [spi_reply(0x6080, 24, b"\xAA" * 24),
                                  spi_reply(0x5000, 1, b"\x01")], True),
]:
    m, writes, box = harness(replies=reps)
    dev = m.Device("/dev/hidraw3")
    got = dev.spi_read(0x5000, 1)
    check("%s -> %s" % (label, "接受" if want else "拒绝"),
          (got is not None) == want, repr(got))

m, writes, box = harness(replies=[spi_reply(0x5000, 1, b"\x01")])
dev = m.Device("/dev/hidraw3")
try:
    dev.spi_read(0x5000, 0x40)
    check("超过 0x1D 的读取被拒绝", False)
except ValueError:
    check("超过 0x1D 的读取被拒绝", True)

print("\n### #5 + #8 + #12 所有非成功退出都必须恢复 0x30")
m, writes, _ = harness(replies=happy_replies()[:2], argv=["x"])
answers = iter(["y", "n"])
real_input = builtins.input
builtins.input = lambda p="": next(answers)
rc = m.main()
builtins.input = real_input
check("取消 -> 退出码 1", rc == 1)
check("取消 -> 恢复 0x30", restored(writes), subcmds(writes))
check("取消 -> 不发 0x07", "0x07" not in subcmds(writes))

m, writes, _ = harness(replies=[reply(0x03), reply(0x30), reply(0x07, ack=0x00), reply(0x03)])
rc = m.main()
check("#8 0x07 NAK 中止 -> 恢复 0x30", restored(writes), subcmds(writes))
check("#8 0x07 NAK 中止 -> 退出码 1", rc == 1)

m, writes, _ = harness(replies=happy_replies()[:3] + [reply(0x08, ack=0x00), reply(0x03)])
m.main()
check("#8 0x08 NAK 中止 -> 恢复 0x30", restored(writes), subcmds(writes))

m, writes, _ = harness(replies=happy_replies()[:4] + [reply(0x03), reply(0x03)])
m.main()
check("#8 回读失败中止 -> 恢复 0x30", restored(writes), subcmds(writes))

# #12: 0x03 0x3F 写成功、但紧接着读失败 -> 手柄可能已在 0x3F，必须恢复
m, writes, _ = harness(replies=[reply(0x03)], read_fail_at=1)
rc = m.main()
check("#12 0x3F 写后读失败 -> 仍恢复 0x30", restored(writes), subcmds(writes))
check("#12 0x3F 写后读失败 -> 退出码 1", rc == 1)

# #12: 0x06 写失败 -> 手柄还开着，必须恢复
# 写入序：03,30,07,08,10,10,10,05,06  -> 第 9 次是 0x06
m, writes, _ = harness(replies=happy_replies(), write_fail_at=9)
rc = m.main()
check("#12 0x06 写失败 -> 仍恢复 0x30", restored(writes), subcmds(writes))
check("#12 0x06 写失败 -> 退出码 1", rc == 1)

m, writes, _ = harness(replies=happy_replies()[:2], argv=["x"])
answers = iter(["y"])
def interrupted(p=""):
    try:
        return next(answers)
    except StopIteration:
        raise KeyboardInterrupt()
builtins.input = interrupted
rc = m.main()
builtins.input = real_input
check("#8 Ctrl-C 于 LED 提示 -> 恢复 0x30", restored(writes), subcmds(writes))
check("#8 Ctrl-C 于 LED 提示 -> 退出码 1", rc == 1)

m, writes, _ = harness(replies=happy_replies()[:2], argv=["x"])
answers = iter(["y"])
def eof(p=""):
    try:
        return next(answers)
    except StopIteration:
        raise EOFError()
builtins.input = eof
try:
    m.main()
    check("#8 EOF 不崩溃", True)
except EOFError:
    check("#8 EOF 不崩溃", False, "EOFError 未捕获")
builtins.input = real_input

print("\n### #14 + #15 恢复过程的中断与提示")
m, writes, _ = harness(replies=happy_replies()[:2], argv=["x"])
answers = iter(["y"])
builtins.input = interrupted
m.Device.restore_input_mode = lambda self: (_ for _ in ()).throw(KeyboardInterrupt())
closed = []
m.os.close = lambda fd: closed.append(fd)
try:
    rc = m.main()
    check("#14 恢复时 Ctrl-C 不逃逸", True)
    check("#14 恢复时 Ctrl-C 仍关闭描述符", closed != [], closed)
    check("#14 恢复时 Ctrl-C 退出码 1", rc == 1, "rc=%s" % rc)
except KeyboardInterrupt:
    check("#14 恢复时 Ctrl-C 不逃逸", False, "KeyboardInterrupt 逃逸了")
builtins.input = real_input

m, writes, _ = harness(replies=happy_replies()[:2], argv=["x"])
answers = iter(["y"])
builtins.input = interrupted
m.Device.restore_input_mode = lambda self: False
rc = m.main()
builtins.input = real_input
check("#8 恢复失败 -> 退出码 1", rc == 1)

# #15: 在 0x07/0x08 之后按 Ctrl-C，不能说"未做任何修改"
m, writes, _ = harness(replies=happy_replies())
orig_subcmd = m.Device.subcmd
def interrupt_shipment(self, cmd, data=b"", **kw):
    if cmd == 0x08:
        self._write(cmd, data)
        raise KeyboardInterrupt()
    return orig_subcmd(self, cmd, data, **kw)
m.Device.subcmd = interrupt_shipment
m.Device.restore_input_mode = lambda self: True
import io as _io
buf = _io.StringIO()
old_stdout = sys.stdout
sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
check("#15 0x07/0x08 后 Ctrl-C 不谎报未修改",
      "未做任何修改" not in out and "已确认收到回复" in out, out.strip().splitlines()[-3:])
check("#15 0x07/0x08 后 Ctrl-C 退出码 1", rc == 1)
check("#19 未确认的 0x08 被如实报告",
      "未确认" in out and "0x08" in out, out.strip().splitlines()[-3:])

# #19: 0x07 写出去、回复还没来就中断 -> 不能声称未修改
m, writes, _ = harness(replies=[reply(0x03), reply(0x30)])
orig_subcmd = m.Device.subcmd
def interrupt_reset(self, cmd, data=b"", **kw):
    if cmd == 0x07:
        self._write(cmd, data)
        raise KeyboardInterrupt()
    return orig_subcmd(self, cmd, data, **kw)
m.Device.subcmd = interrupt_reset
m.Device.restore_input_mode = lambda self: True
buf = _io.StringIO(); sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
check("#19 0x07 在途中断 -> 报告未确认",
      "未做任何修改" not in out and "未确认" in out and "0x07" in out,
      out.strip().splitlines()[-3:])

print("\n### #20 USB 必须无条件拒绝，且什么都不发")
m, writes, _ = harness(replies=happy_replies(), argv=["x"])
m.find_devices = lambda: ([("/dev/hidraw9", 0x2009, "Pro Controller", "usb", None)], [])
answers = iter(["y", "y", "y"])   # 即使全部答 y，也不得放行
builtins.input = lambda p="": next(answers)
buf = _io.StringIO(); sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
builtins.input = real_input
check("#20 USB 下退出码 1", rc == 1, "rc=%s" % rc)
check("#20 USB 下什么命令都不发", writes == [], subcmds(writes))
check("#20 USB 下不写 flash（0x07 未发）", "0x07" not in subcmds(writes))
check("#20 USB 下不写 flash（0x08 未发）", "0x08" not in subcmds(writes))
check("#20 USB 下不发 0x06", "0x06" not in subcmds(writes))
check("#20 USB 下不声称已断电", "手柄应已断电" not in out, out.strip().splitlines()[-3:])
check("#20 USB 下说明不给绕过选项", "不给绕过选项" in out, out.strip().splitlines()[-5:])

# 未知总线同样拒绝
m, writes, _ = harness(replies=happy_replies(), argv=["x", "--yes"])
m.find_devices = lambda: ([("/dev/hidraw9", 0x2009, "Pro Controller", "bus 0001", None)], [])
rc = m.main()
check("#20 未知总线 -> 退出码 1", rc == 1, "rc=%s" % rc)
check("#20 未知总线 -> 什么都不发", writes == [], subcmds(writes))
print("\n### #21 失败提示不得超出校验所能确立的范围")
m, writes, _ = harness(replies=happy_replies()[:4])
buf = _io.StringIO(); sys.stdout = buf
try:
    m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
check("#21 回读超时不说「不会进入低功耗」",
      "不会进入真正的低功耗态" not in out and "无法确认" in out, out.strip().splitlines()[-4:])
check("#26 abort 不再许诺「手柄仍可正常使用」",
      "手柄仍可正常使用" not in out, out.strip().splitlines()[-4:])
check("#24 abort 也报告已完成/未确认状态",
      "已确认收到回复" in out, out.strip().splitlines()[-4:])

print("\n### #22 dry-run 必须预览全部命令")
m, writes, _ = harness(replies=[], argv=["x", "--yes", "--dry-run"])
buf = _io.StringIO(); sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
check("#22 dry-run 退出码 0", rc == 0, "rc=%s" % rc)
check("#22 dry-run 不发真实命令", writes == [])
for name, pat in [("0x03 3F", "03 3F"), ("0x07", "40 40 07"),
                  ("0x08 01", "08 01"), ("0x10 读 0x5000", "10 00 50 00 00 01"),
                  ("0x10 读 0x2000", "10 00 20 00 00 01"),
                  ("0x10 读 0x2026", "10 26 20 00 00 01"),
                  ("0x05", "40 40 05"), ("0x06 00", "06 00")]:
    check("#22 dry-run 预览 %s" % name, pat in out, pat)

print("\n### #31 中断措辞不得超出实际发生的范围")
m, writes, _ = harness(replies=[reply(0x03), reply(0x30), reply(0x03)])
orig = m.Device.subcmd
def interrupt_before_flash(self, cmd, data=b"", **kw):
    if cmd == 0x30:      # LED 命令：在 track() 之前，ops 还是空的
        raise KeyboardInterrupt()
    return orig(self, cmd, data, **kw)
m.Device.subcmd = interrupt_before_flash
buf = _io.StringIO(); sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
check("#31 flash 写入前中断 -> 不说「未做任何修改」",
      "未做任何修改" not in out, out.strip().splitlines()[-2:])
check("#31 flash 写入前中断 -> 如实说未执行 flash 写入",
      "未执行 flash 写入" in out, out.strip().splitlines()[-2:])
check("#31 flash 写入前中断 -> 退出码 1", rc == 1, "rc=%s" % rc)

print("\n### #28 + #29 + #30 记账不得漏报/虚报")

# #29: dry-run 中断不得声称收到确认
m, writes, _ = harness(replies=[], argv=["x", "--dry-run"])
orig = m.Device.subcmd
def dry_interrupt(self, cmd, data=b"", **kw):
    if cmd == 0x07:
        raise KeyboardInterrupt()
    return orig(self, cmd, data, **kw)
m.Device.subcmd = dry_interrupt
buf = _io.StringIO(); sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
check("#29 dry-run 中断不声称收到确认", "已确认收到回复" not in out, out.strip().splitlines()[-2:])
check("#29 dry-run 中断不说手柄处于中间状态", "中间状态" not in out, out.strip().splitlines()[-2:])
check("#29 dry-run 中断退出码 1", rc == 1, "rc=%s" % rc)

# #28: 0x07 已确认后立刻中断 -> 不得说"未做任何修改"
m, writes, _ = harness(replies=[reply(0x03), reply(0x30), reply(0x07)])
orig = m.Device.subcmd
def interrupt_after_ack(self, cmd, data=b"", **kw):
    r = orig(self, cmd, data, **kw)
    if cmd == 0x07:
        raise KeyboardInterrupt()
    return r
m.Device.subcmd = interrupt_after_ack
m.Device.restore_input_mode = lambda self: True
buf = _io.StringIO(); sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
check("#28 0x07 确认后中断 -> 不谎报未修改",
      "未做任何修改" not in out, out.strip().splitlines()[-3:])
check("#28 0x07 确认后中断 -> 报告 0x07 已发出",
      "0x07" in out and ("已确认收到回复" in out or "未确认" in out),
      out.strip().splitlines()[-3:])

# #30: 0x06 发出后中断 -> 必须报告 0x06 已发出
m, writes, _ = harness(replies=happy_replies() + [reply(0x03)])
orig = m.Device.subcmd
def interrupt_after_off(self, cmd, data=b"", **kw):
    r = orig(self, cmd, data, **kw)
    if cmd == 0x06:
        raise KeyboardInterrupt()
    return r
m.Device.subcmd = interrupt_after_off
buf = _io.StringIO(); sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
check("#30 0x06 发出后中断 -> 报告里含 0x06",
      "0x06" in out, out.strip().splitlines()[-4:])
check("#30 0x06 发出后中断 -> 不谎报未修改", "未做任何修改" not in out)
check("#30 0x06 发出后中断 -> 退出码 1", rc == 1, "rc=%s" % rc)

print("\n### #27 USB dry-run 同样拒绝，不得声称已处理")
m, writes, _ = harness(replies=[], argv=["x", "--dry-run"])
m.find_devices = lambda: ([("/dev/hidraw9", 0x2009, "Pro Controller", "usb", None)], [])
answers = iter(["y", "y", "y"])
builtins.input = lambda p="": next(answers)
buf = _io.StringIO(); sys.stdout = buf
try:
    rc = m.main()
finally:
    sys.stdout = old_stdout
out = buf.getvalue()
builtins.input = real_input
check("#27 USB dry-run 退出码 1", rc == 1, "rc=%s" % rc)
check("#27 USB dry-run 不发命令", writes == [])
check("#27 USB dry-run 不声称已处理", "已处理" not in out, out.strip().splitlines()[-3:])
check("#27 USB dry-run 不指示拔线", "手动断开 USB" not in out, out.strip().splitlines()[-3:])
check("#27 USB dry-run 不预览任何包", "40 40 07" not in out, out.strip().splitlines()[-3:])
print("\n### #6 操作中途断开必须被捕获")
for label, kw in [("写失败", {"write_raises": True}), ("读失败", {"read_raises": True})]:
    m, writes, _ = harness(replies=happy_replies(), **kw)
    m.Device.restore_input_mode = lambda self: False
    try:
        rc = m.main()
        check("%s -> 捕获并返回 1" % label, rc == 1, "rc=%s" % rc)
    except OSError as e:
        check("%s -> 捕获并返回 1" % label, False, "未捕获: %s" % e)

print("\n### #9 + #13 + #18 配对门禁：SPI 槽魔数是判据，0x05 只作参考")
m, writes, _ = harness(replies=happy_replies(pairing=(0x95, 0xFF)))
rc = m.main()
check("#9 槽1 仍是 0x95 -> 不发 0x06", "0x06" not in subcmds(writes), subcmds(writes))
check("#9 槽1 仍是 0x95 -> 退出码 1", rc == 1)
check("#9 槽1 仍是 0x95 -> 恢复 0x30", restored(writes))

m, writes, _ = harness(replies=happy_replies(pairing=(0x00, 0x95)))
m.main()
check("#13 槽2 仍是 0x95（槽1 是上一个配对）-> 不发 0x06",
      "0x06" not in subcmds(writes), subcmds(writes))

m, writes, _ = harness(replies=happy_replies(pairing=(0xFF, 0xFF)))
rc = m.main()
check("槽已清除 -> 发 0x06", "0x06" in subcmds(writes))
check("槽已清除 -> 退出码 0", rc == 0, "rc=%s" % rc)

m, writes, _ = harness(replies=happy_replies()[:5])   # 配对槽回读无回复
m.main()
check("配对槽读不到 -> 不发 0x06", "0x06" not in subcmds(writes), subcmds(writes))

# #18: 0x05 语义未经证实，不能当门禁
m, writes, _ = harness(replies=happy_replies(page_list=0x01))
rc = m.main()
check("#18 0x05 返回 0x01 不再中止（只作参考）", rc == 0 and "0x06" in subcmds(writes),
      "rc=%s %s" % (rc, subcmds(writes)))

m, writes, _ = harness(replies=happy_replies()[:7])   # 0x05 无回复
rc = m.main()
check("#18 0x05 超时不再中止", rc == 0 and "0x06" in subcmds(writes),
      "rc=%s %s" % (rc, subcmds(writes)))

check("#13 槽数常量存在且为 2", getattr(load(), "PAIRING_SLOTS", None) == 2)
check("#18 page_list_state 存在（降级为参考值）", hasattr(load(), "page_list_state"))

print("\n### #17 drain 必须有上限")
m = load()


class AlwaysReadable:
    """永远有数据可读的假 transport，用来验证 drain 不会死循环。"""
    reads = 0

    def poll(self):
        return True

    def read_nowait(self):
        AlwaysReadable.reads += 1
        return b"\x00" * m.REPORT_LEN


dev = m.Device("/dev/hidraw3", dry=True)
dev.dry = False
dev._t = AlwaysReadable()
dev.drain()
check("#17 drain 在一直可读时不死循环", AlwaysReadable.reads == m.DRAIN_MAX,
      "读了 %d 次，上限 %d" % (AlwaysReadable.reads, m.DRAIN_MAX))
print("\n### 回归：正常流程 / dry-run / USB 拒绝")
m, writes, _ = harness(replies=happy_replies())
rc = m.main()
check("正常流程退出码 0", rc == 0, "rc=%s" % rc)
check("子命令序列正确",
      subcmds(writes) == ["0x03", "0x30", "0x07", "0x08", "0x10", "0x10", "0x10", "0x05", "0x06"],
      subcmds(writes))
check("包序号 0..8", [w[1] for w in writes] == list(range(9)))
check("每条都是 64 字节", all(len(w) == 64 for w in writes))
check("成功路径不恢复 0x30（手柄已断电）", not restored(writes))
check("0x08 参数 0x01", any(w[10] == 0x08 and w[11] == 0x01 for w in writes))
check("0x06 参数 0x00", any(w[10] == 0x06 and w[11] == 0x00 for w in writes))

m, writes, _ = harness(replies=[], argv=["x", "--yes", "--dry-run"])
rc = m.main()
check("dry-run 退出码 0", rc == 0, "rc=%s" % rc)
check("dry-run 不发真实命令", writes == [])

m, writes, _ = harness(replies=[], argv=["x", "--yes"])
m.find_devices = lambda: ([("/dev/hidraw9", 0x2009, "Pro Controller", "usb", None)], [])
rc = m.main()
check("--yes + USB -> 退出码 1", rc == 1)
check("--yes + USB -> 不发命令", writes == [])

print("\n### 单元：drain 在 write 之前")
m = load()
order = []
m.os = type("O", (), {"O_RDWR": os.O_RDWR, "path": os.path,
                      "open": staticmethod(lambda p, f: 42),
                      "close": staticmethod(lambda fd: None),
                      "write": staticmethod(lambda fd, d: order.append("write") or len(d))})()
m.select = type("S", (), {"select": staticmethod(lambda r, w, x, t: ([], [], []))})()
m.time.sleep = lambda s: None
m.Device.drain = lambda self: order.append("drain")
dev = m.Device("/dev/hidraw3")
dev.subcmd(0x07)
check("drain 在 write 之前", order[:2] == ["drain", "write"], order[:2])

print("\n" + "=" * 60)
print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
if FAIL:
    for f in FAIL:
        print("  ✗ " + f)
    sys.exit(1)
print("全部通过")
