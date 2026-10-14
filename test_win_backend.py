"""Windows 后端专项测试：用 mock 覆盖 review 修复的每个点。

在 Windows Python 上运行（需要 ctypes.WinDLL）。
    py -3 test_win_backend.py
"""
import ctypes
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "joycon-poweroff.py")

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  %s %s%s" % ("OK  " if cond else "FAIL", name,
                         ("  -- " + str(detail)) if detail else ""))


def load():
    spec = importlib.util.spec_from_file_location("jc", SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


if sys.platform != "win32":
    print("这个测试只能在 Windows 上跑（需要 ctypes.WinDLL）")
    sys.exit(0)

m = load()
print("=== Windows 后端测试 ===\n")

# ---------------------------------------------------------------- P1-1 写路径
print("### P1-1 WriteFile 必须带专属 OVERLAPPED，字节数用 GetOverlappedResult")
calls = {"writefile": [], "wait": [], "gor": []}
real_writefile = m._KERNEL32.WriteFile
real_gor = m._KERNEL32.GetOverlappedResult
real_wait = m._KERNEL32.WaitForSingleObject


def fake_writefile(h, buf, n, written, ov):
    calls["writefile"].append({"written_ptr": written, "overlapped": ov})
    return True


def fake_wait_ok(h, ms):
    calls["wait"].append(ms)
    return 0        # WAIT_OBJECT_0


def fake_gor(h, ov, n, wait):
    calls["gor"].append({"wait": wait})
    n._obj.value = 64
    return True


# 用一个真实设备打开 transport（键盘），只替换 WriteFile/等待函数
target = None
for path, devinst in m._win_enumerate():
    try:
        t = m._WinTransport(path)
    except OSError:
        continue
    target = t
    break

if target is None:
    print("  跳过（没有可打开的设备）")
else:
    m._KERNEL32.WriteFile = fake_writefile
    m._KERNEL32.WaitForSingleObject = fake_wait_ok
    m._KERNEL32.GetOverlappedResult = fake_gor
    try:
        target.write(bytes(64))
    except Exception as e:
        check("write() 成功", False, e)
    else:
        check("write() 成功", True)
    finally:
        m._KERNEL32.WriteFile = real_writefile
        m._KERNEL32.WaitForSingleObject = real_wait
        m._KERNEL32.GetOverlappedResult = real_gor

    wf = calls["writefile"][0]
    check("lpNumberOfBytesWritten 传了 NULL（异步要求）",
          wf["written_ptr"] is None, wf["written_ptr"])
    check("传了非空 OVERLAPPED",
          wf["overlapped"] is not None and bool(wf["overlapped"]))
    check("写用的 OVERLAPPED 与读的不是同一个",
          wf["overlapped"] != target.overlapped)
    check("写等待有上限",
          calls["wait"] and calls["wait"][0] == m._WRITE_WAIT_MS, calls["wait"])
    check("收尾用 GetOverlappedResult(bWait=False)",
          calls["gor"] and calls["gor"][0]["wait"] is False, calls["gor"])

    # 短写必须报错
    def short_gor(h, ov, n, wait):
        n._obj.value = 10
        return True
    m._KERNEL32.WriteFile = fake_writefile
    m._KERNEL32.WaitForSingleObject = fake_wait_ok
    m._KERNEL32.GetOverlappedResult = short_gor
    try:
        target.write(bytes(64))
        check("短写被拒绝", False, "没有报错")
    except OSError as e:
        check("短写被拒绝", "短写" in str(e), e)
    finally:
        m._KERNEL32.WriteFile = real_writefile
        m._KERNEL32.WaitForSingleObject = real_wait
        m._KERNEL32.GetOverlappedResult = real_gor
    target.close()

# ------------------------------------------------------- P1-3 pending 置位时机
print("\n### P1-3 pending 必须在提交前置位，失败时回滚")
t = m._WinTransport.__new__(m._WinTransport)
t.handle = 1
t.report_len = 64
t.buf = ctypes.create_string_buffer(64)
t.overlapped = m._OVERLAPPED()
t.event = 1
t.overlapped.hEvent = 1
t.pending = False
t.write_pending = False

seen = {}


def fake_readfile_raising(h, buf, n, written, ov):
    seen["pending_during_call"] = t.pending   # 调用瞬间就该是 True
    ctypes.set_last_error(87)                  # ERROR_INVALID_PARAMETER
    return False


real_readfile = m._KERNEL32.ReadFile
m._KERNEL32.ReadFile = fake_readfile_raising
try:
    t._start_read()
    check("提交失败时抛异常", False, "没有抛")
except OSError:
    check("提交失败时抛异常", True)
finally:
    m._KERNEL32.ReadFile = real_readfile
check("ReadFile 调用期间 pending 已置位", seen.get("pending_during_call") is True,
      seen)
check("提交失败后 pending 回滚为 False", t.pending is False, t.pending)

# ERROR_IO_PENDING 是正常提交，不能当失败
def fake_readfile_pending(h, buf, n, written, ov):
    ctypes.set_last_error(997)   # ERROR_IO_PENDING
    return False


m._KERNEL32.ReadFile = fake_readfile_pending
try:
    t._start_read()
    check("ERROR_IO_PENDING 不当失败", t.pending is True, t.pending)
except OSError as e:
    check("ERROR_IO_PENDING 不当失败", False, e)
finally:
    m._KERNEL32.ReadFile = real_readfile

# --------------------------------------------------- P1-3 ERROR_IO_INCOMPLETE
print("\n### P1-3 ERROR_IO_INCOMPLETE 不能清 pending")


def fake_gor_incomplete(h, ov, n, wait):
    ctypes.set_last_error(996)   # ERROR_IO_INCOMPLETE
    return False


m._KERNEL32.GetOverlappedResult = fake_gor_incomplete
t.pending = True
try:
    r = t._collect()
    check("未完成时返回 None 而不是抛异常", r is None, r)
    check("未完成时保持 pending=True", t.pending is True, t.pending)
except OSError as e:
    check("未完成时返回 None 而不是抛异常", False, e)
finally:
    m._KERNEL32.GetOverlappedResult = real_gor

# ------------------------------------------------------------- P1-2 close 语义
print("\n### P1-2 close() 必须等取消真正完成再释放")
order = []
real_cancelioex = m._KERNEL32.CancelIoEx
real_closehandle = m._KERNEL32.CloseHandle
real_wait = m._KERNEL32.WaitForSingleObject


def fake_cancelioex(h, ov):
    order.append("cancel")
    return True


def fake_wait_single(h, ms):
    order.append("wait")
    return 0        # WAIT_OBJECT_0：取消已生效


def fake_gor_wait(h, ov, n, wait):
    order.append("reap")
    n._obj.value = 0
    ctypes.set_last_error(995)   # ERROR_OPERATION_ABORTED
    return False


def fake_closehandle(h):
    order.append("close")
    return True


t2 = m._WinTransport.__new__(m._WinTransport)
t2.handle = 1
t2.event = 2
t2.wevent = 3
t2.overlapped = m._OVERLAPPED()
t2.woverlapped = m._OVERLAPPED()
t2.pending = True
t2.write_pending = False

m._KERNEL32.CancelIoEx = fake_cancelioex
m._KERNEL32.WaitForSingleObject = fake_wait_single
m._KERNEL32.GetOverlappedResult = fake_gor_wait
m._KERNEL32.CloseHandle = fake_closehandle
try:
    t2.close()
finally:
    m._KERNEL32.CancelIoEx = real_cancelioex
    m._KERNEL32.WaitForSingleObject = real_wait
    m._KERNEL32.GetOverlappedResult = real_gor
    m._KERNEL32.CloseHandle = real_closehandle

check("取消后先等完成再关闭句柄",
      order[:3] == ["cancel", "wait", "reap"] and "close" in order[3:], order)
check("close() 后 handle 置空", t2.handle is None, t2.handle)
check("close() 后 event 置空", t2.event is None and t2.wevent is None)
check("close() 后 pending 为 False", t2.pending is False)

# 等待超时时不能永久挂住（驱动卡死场景）
order2 = []
t3 = m._WinTransport.__new__(m._WinTransport)
t3.handle = 1
t3.event = 2
t3.wevent = 3
t3.buf = ctypes.create_string_buffer(64)
t3.overlapped = m._OVERLAPPED()
t3.woverlapped = m._OVERLAPPED()
t3.pending = True
t3.write_pending = False


def fake_wait_timeout(h, ms):
    order2.append(("wait", ms))
    return 258      # WAIT_TIMEOUT


def fake_close_into_order2(h):
    order2.append(("close", h))
    return True


m._KERNEL32.CancelIoEx = fake_cancelioex
m._KERNEL32.WaitForSingleObject = fake_wait_timeout
m._KERNEL32.CloseHandle = fake_close_into_order2
q_before = len(m._QUARANTINE)
try:
    t3.close()
    check("等待有上限，不会永久挂住", True)
    check("等待用的是有限超时",
          order2 and order2[0][1] == m._CLOSE_WAIT_MS, order2)
    check("超时后句柄也一并保留（不关闭）", t3.handle == 1, t3.handle)
    check("超时后整个 transport 被扣住（不释放）",
          len(m._QUARANTINE) == q_before + 1, len(m._QUARANTINE))
    check("被扣住的正是这个 transport", m._QUARANTINE[-1] is t3)
    check("被扣住后 buf/overlapped/event 仍可达（未被释放）",
          t3.buf is not None and t3.overlapped is not None
          and t3.event is not None)
    check("被扣住的 event 没被 CloseHandle",
          ("close", 2) not in order2, order2)
    check("被扣住的 event 确实没关（句柄 2 不在关闭列表里）",
          all(h != 2 for tag, h in order2 if tag == "close"), order2)
except Exception as e:
    check("等待有上限，不会永久挂住", False, e)
finally:
    m._KERNEL32.CancelIoEx = real_cancelioex
    m._KERNEL32.WaitForSingleObject = real_wait
    m._KERNEL32.CloseHandle = real_closehandle

print("\n### P1-1 先扣住再取消：取消阶段被打断也不能释放")
real_cancel4 = m._KERNEL32.CancelIoEx
real_wait4 = m._KERNEL32.WaitForSingleObject
real_close4 = m._KERNEL32.CloseHandle

t6 = m._WinTransport.__new__(m._WinTransport)
t6.handle = 1
t6.event = 2
t6.wevent = 3
t6.buf = ctypes.create_string_buffer(64)
t6.wbuf = ctypes.create_string_buffer(64)
t6.overlapped = m._OVERLAPPED()
t6.woverlapped = m._OVERLAPPED()
t6.pending = True
t6.write_pending = False


def cancel_interrupted(h, ov):
    raise KeyboardInterrupt()


m._KERNEL32.CancelIoEx = cancel_interrupted
m._KERNEL32.WaitForSingleObject = fake_wait_timeout
m._KERNEL32.CloseHandle = fake_close_into_order2
q_before = len(m._QUARANTINE)
try:
    t6.close()
except KeyboardInterrupt:
    check("取消阶段被打断会向上抛", True)
else:
    check("取消阶段被打断会向上抛", False, "没有抛")
finally:
    m._KERNEL32.CancelIoEx = real_cancel4
    m._KERNEL32.WaitForSingleObject = real_wait4
    m._KERNEL32.CloseHandle = real_close4

check("取消阶段被打断时已扣住（资源不会释放）",
      len(m._QUARANTINE) == q_before + 1, len(m._QUARANTINE))
check("扣住的正是这个 transport", m._QUARANTINE[-1] is t6)
check("被打断后 buf/overlapped 仍可达",
      t6.buf is not None and t6.overlapped is not None)

# 确认结束后必须移出扣留名单（不能永久扣着健康的 transport）
real_cancel5 = m._KERNEL32.CancelIoEx
real_wait5 = m._KERNEL32.WaitForSingleObject
real_gor5 = m._KERNEL32.GetOverlappedResult
real_close5 = m._KERNEL32.CloseHandle

t7 = m._WinTransport.__new__(m._WinTransport)
t7.handle = 1
t7.event = 2
t7.wevent = 3
t7.buf = ctypes.create_string_buffer(64)
t7.wbuf = ctypes.create_string_buffer(64)
t7.overlapped = m._OVERLAPPED()
t7.woverlapped = m._OVERLAPPED()
t7.pending = True
t7.write_pending = False

m._KERNEL32.CancelIoEx = lambda h, ov: True
m._KERNEL32.WaitForSingleObject = fake_wait_ok
m._KERNEL32.GetOverlappedResult = lambda h, ov, n, wait: True
m._KERNEL32.CloseHandle = lambda h: True
q_before = len(m._QUARANTINE)
try:
    t7.close()
    check("读确认结束后从扣留名单移出",
          len(m._QUARANTINE) == q_before, len(m._QUARANTINE))
    check("移出后正常关闭句柄", t7.handle is None)
finally:
    m._KERNEL32.CancelIoEx = real_cancel5
    m._KERNEL32.WaitForSingleObject = real_wait5
    m._KERNEL32.GetOverlappedResult = real_gor5
    m._KERNEL32.CloseHandle = real_close5

print("\n### P2-4 写操作也必须有等待上限")
real_wait2 = m._KERNEL32.WaitForSingleObject
real_writefile2 = m._KERNEL32.WriteFile

t4 = m._WinTransport.__new__(m._WinTransport)
t4.handle = 1
t4.wbuf = ctypes.create_string_buffer(64)
t4.woverlapped = m._OVERLAPPED()
t4.wevent = 2
t4.woverlapped.hEvent = 2
t4.pending = False
t4.write_pending = False


def fake_writefile_pending2(h, buf, n, written, ov):
    ctypes.set_last_error(997)   # ERROR_IO_PENDING
    return False


m._KERNEL32.WriteFile = fake_writefile_pending2
m._KERNEL32.WaitForSingleObject = fake_wait_timeout   # 永不信号
q_before = len(m._QUARANTINE)
try:
    t4.write(bytes(64))
    check("写超时会报错", False, "没有抛")
except OSError as e:
    check("写超时会报错", "未在" in str(e) and "未知" in str(e), e)
    check("写超时后整个 transport 被扣住", len(m._QUARANTINE) == q_before + 1,
          len(m._QUARANTINE))
    check("写超时后 wbuf/woverlapped 仍可达（未被释放）",
          t4.wbuf is not None and t4.woverlapped is not None)
    check("写超时后 write_pending 保持 True（后续写入继续被拒）",
          t4.write_pending is True, t4.write_pending)
finally:
    m._KERNEL32.WriteFile = real_writefile2
    m._KERNEL32.WaitForSingleObject = real_wait2

print("\n### P1-1 write_pending：未决的写不能被重用")
real_writefile3 = m._KERNEL32.WriteFile
real_wait3 = m._KERNEL32.WaitForSingleObject

t5 = m._WinTransport.__new__(m._WinTransport)
t5.handle = 1
t5.wbuf = ctypes.create_string_buffer(64)
t5.woverlapped = m._OVERLAPPED()
t5.wevent = 2
t5.woverlapped.hEvent = 2
t5.pending = False
t5.write_pending = False

m._KERNEL32.WriteFile = fake_writefile_pending2
m._KERNEL32.WaitForSingleObject = fake_wait_timeout

# 模拟：提交后、等待中被 Ctrl-C 打断（write_pending 仍为 True）
def wait_interrupted(h, ms):
    raise KeyboardInterrupt()


m._KERNEL32.WaitForSingleObject = wait_interrupted
try:
    t5.write(bytes(64))
except KeyboardInterrupt:
    check("等待中被 Ctrl-C 会向上抛", True)
else:
    check("等待中被 Ctrl-C 会向上抛", False, "没有抛")
finally:
    m._KERNEL32.WaitForSingleObject = real_wait3

check("被中断后 write_pending 仍为 True（资源未交出）",
      t5.write_pending is True, t5.write_pending)
check("被中断后 wbuf 仍在（未被释放）", t5.wbuf is not None)

# 关键：此时再写必须被拒绝，不能重用 OVERLAPPED
m._KERNEL32.WriteFile = fake_writefile_pending2
m._KERNEL32.WaitForSingleObject = fake_wait_ok
try:
    t5.write(bytes(64))
    check("未决的写会阻止后续写入（不重用 OVERLAPPED）", False, "居然允许了")
except OSError as e:
    check("未决的写会阻止后续写入（不重用 OVERLAPPED）",
          "尚未确认完成" in str(e), e)
finally:
    m._KERNEL32.WriteFile = real_writefile3
    m._KERNEL32.WaitForSingleObject = real_wait3

# close() 必须把未决的写也扣住
q_before = len(m._QUARANTINE)
real_cancel3 = m._KERNEL32.CancelIoEx
real_close3b = m._KERNEL32.CloseHandle
m._KERNEL32.CancelIoEx = lambda h, ov: True
m._KERNEL32.CloseHandle = lambda h: True
try:
    t5.close()
    check("close() 扣住整个 transport",
          len(m._QUARANTINE) == q_before + 1, len(m._QUARANTINE))
    check("close() 扣住后 wbuf 仍可达", t5.wbuf is not None)
    check("close() 扣住后不关闭 wevent",
          all(h != 2 for tag, h in order2 if tag == "close") if order2 else True)
finally:
    m._KERNEL32.CancelIoEx = real_cancel3
    m._KERNEL32.CloseHandle = real_close3b

print("\n### P2-3 接口能力未知必须拒绝，不能当成“不可写”")
real_enumerate3 = m._win_enumerate
real_open3 = m._win_open
real_attrs3 = m._win_read_attrs
real_outlen3 = m._win_output_report_len
real_parent3 = m._win_parent_id
real_bus3 = m._win_bus_of
real_close3 = m._KERNEL32.CloseHandle

m._win_enumerate = lambda: iter([("\\path\\a", 1), ("\\path\\b", 2)])
m._win_open = lambda p, overlapped=False: (1 if p.endswith("a") else 2)
m._win_read_attrs = lambda h: (m.NINTENDO_VID, 0x2007, None)
m._win_parent_id = lambda d: "SAME_PARENT"
m._win_bus_of = lambda d: "bluetooth"
m._KERNEL32.CloseHandle = lambda h: True

# a 可写、b 能力未知 -> 必须拒绝
def outlen_unknown(h):
    return 64 if h == 1 else None


m._win_output_report_len = outlen_unknown
try:
    found, skipped = m._win_find_devices()
    check("一个可写 + 一个未知 -> 拒绝而不是选可写的那个",
          len(found) == 0 and len(skipped) == 1,
          "found=%d skipped=%d" % (len(found), len(skipped)))
    check("提示说明是能力未知",
          skipped and "能力未知" in skipped[0][2],
          skipped[0][2] if skipped else None)

    # 两个都可写 -> 拒绝
    m._win_output_report_len = lambda h: 64
    found, skipped = m._win_find_devices()
    check("两个都可写 -> 拒绝", len(found) == 0 and len(skipped) == 1,
          "found=%d" % len(found))

    # 一个可写、一个确定不可写 -> 选中可写的
    m._win_output_report_len = lambda h: 64 if h == 1 else 0
    found, skipped = m._win_find_devices()
    check("一个可写 + 一个确定不可写 -> 正常选中",
          len(found) == 1 and len(skipped) == 0,
          "found=%d skipped=%d" % (len(found), len(skipped)))

    # 都确定不可写 -> 拒绝
    m._win_output_report_len = lambda h: 0
    found, skipped = m._win_find_devices()
    check("都不可写 -> 拒绝", len(found) == 0 and len(skipped) == 1,
          "found=%d" % len(found))

    # 兄弟接口打不开 -> 必须拒绝（不能因为“只剩一个”就选中）
    m._win_output_report_len = lambda h: 64
    m._win_enumerate = lambda: iter([("\\path\\a", 1), ("\\path\\b", 2)])

    def open_b_fails(p, overlapped=False):
        if p.endswith("b"):
            raise OSError(5, "denied")
        return 1

    m._win_open = open_b_fails
    found, skipped = m._win_find_devices()
    check("兄弟接口打不开 -> 拒绝而不是选中剩下那个",
          len(found) == 0 and len(skipped) == 1,
          "found=%d skipped=%d" % (len(found), len(skipped)))
    check("提示说明是兄弟接口读不到",
          skipped and "读不到" in skipped[0][2],
          skipped[0][2] if skipped else None)

    # 兄弟接口属性读不到（能打开但拿不到 VID/PID）-> 同样拒绝
    m._win_open = lambda p, overlapped=False: (1 if p.endswith("a") else 2)
    m._win_read_attrs = lambda h: ((m.NINTENDO_VID, 0x2007, None) if h == 1
                                   else (None, None, None))
    found, skipped = m._win_find_devices()
    check("兄弟接口属性读不到 -> 拒绝",
          len(found) == 0 and len(skipped) == 1,
          "found=%d skipped=%d" % (len(found), len(skipped)))
    m._win_read_attrs = lambda h: (m.NINTENDO_VID, 0x2007, None)
finally:
    m._win_enumerate = real_enumerate3
    m._win_open = real_open3
    m._win_read_attrs = real_attrs3
    m._win_output_report_len = real_outlen3
    m._win_parent_id = real_parent3
    m._win_bus_of = real_bus3
    m._KERNEL32.CloseHandle = real_close3

# ------------------------------------------------------------------ P3-8 错误映射
print("\n### P3-8 Windows 错误码不能当 POSIX errno")


def fake_createevent_fail(*a):
    ctypes.set_last_error(8)     # ERROR_NOT_ENOUGH_MEMORY
    return None


real_createevent = m._KERNEL32.CreateEventW
real_open = m._win_open
m._KERNEL32.CreateEventW = fake_createevent_fail
m._win_open = lambda p, overlapped=False: 1
try:
    m._WinTransport("fake")
    check("CreateEventW 失败时抛异常", False, "没有抛")
except OSError as e:
    check("CreateEventW 失败时抛异常", True)
    check("错误码是原始值 8（未被 CloseHandle 覆盖）",
          getattr(e, "winerror", None) == 8, getattr(e, "winerror", None))
    check("异常带 winerror 属性", hasattr(e, "winerror"))
finally:
    m._KERNEL32.CreateEventW = real_createevent
    m._win_open = real_open

# 检查 OSError 映射是否正确（用 WinError 而非裸 errno）
e = m._win_error(32, "test")
check("错误 32 映射为 winerror=32（不是 POSIX BrokenPipe）",
      getattr(e, "winerror", None) == 32, getattr(e, "winerror", None))
check("错误 32 不是 BrokenPipeError", not isinstance(e, BrokenPipeError),
      type(e).__name__)

# ---------------------------------------------------------------- P2-5/P2-6
print("\n### P2-5 总线判断失败必须拒绝（不能靠路径 UUID 兜底）")
check("_BT_HID_UUID 已删除（不再靠路径子串放行）",
      not hasattr(m, "_BT_HID_UUID"))

print("\n### P2-6 去重歧义必须拒绝而不是猜")
# 构造一个假的枚举：同一父设备下两个可写接口
fake_entries = [
    ("\\path\\a", 1), ("\\path\\b", 1),
]
real_enumerate = m._win_enumerate
real_open2 = m._win_open
real_attrs = m._win_read_attrs
real_outlen = m._win_output_report_len
real_parent = m._win_parent_id
real_bus = m._win_bus_of
real_close = m._KERNEL32.CloseHandle

m._win_enumerate = lambda: iter(fake_entries)
m._win_open = lambda p, overlapped=False: 1
m._win_read_attrs = lambda h: (m.NINTENDO_VID, 0x2007, None)
m._win_output_report_len = lambda h: 64      # 两个都非零 -> 歧义
m._win_parent_id = lambda d: "SAME_PARENT"
m._win_bus_of = lambda d: "bluetooth"
m._KERNEL32.CloseHandle = lambda h: True
try:
    found, skipped = m._win_find_devices()
    check("两个可写接口 -> 进 skipped 而不是随便挑一个",
          len(found) == 0 and len(skipped) == 1, "found=%d skipped=%d" % (len(found), len(skipped)))
    check("提示里说明是歧义", "无法确定" in skipped[0][2], skipped[0][2] if skipped else None)

    # 只有一个可写 -> 正常选中
    m._win_output_report_len = lambda h: 64 if h == 1 else 0
    m._win_enumerate = lambda: iter([("\\path\\a", 1), ("\\path\\b", 2)])
    m._win_open = lambda p, overlapped=False: (1 if p.endswith("a") else 2)
    found, skipped = m._win_find_devices()
    check("只有一个可写接口 -> 正常选中", len(found) == 1 and len(skipped) == 0,
          "found=%d skipped=%d" % (len(found), len(skipped)))
finally:
    m._win_enumerate = real_enumerate
    m._win_open = real_open2
    m._win_read_attrs = real_attrs
    m._win_output_report_len = real_outlen
    m._win_parent_id = real_parent
    m._win_bus_of = real_bus
    m._KERNEL32.CloseHandle = real_close

# ------------------------------------------------------------------ P3-9 枚举
print("\n### P3-9 枚举失败不能伪装成枚举结束")
real_enum_iface = m._SETUPAPI.SetupDiEnumDeviceInterfaces
real_getclass = m._SETUPAPI.SetupDiGetClassDevsW
real_destroy = m._SETUPAPI.SetupDiDestroyDeviceInfoList
m._SETUPAPI.SetupDiGetClassDevsW = lambda *a: 1
m._SETUPAPI.SetupDiDestroyDeviceInfoList = lambda h: True


def enum_real_error(h, d, g, i, did):
    ctypes.set_last_error(87)    # ERROR_INVALID_PARAMETER
    return False


m._SETUPAPI.SetupDiEnumDeviceInterfaces = enum_real_error
try:
    list(m._win_enumerate())
    check("真实枚举错误会抛异常", False, "静默返回了")
except OSError as e:
    check("真实枚举错误会抛异常", True, e)
finally:
    m._SETUPAPI.SetupDiEnumDeviceInterfaces = real_enum_iface
    m._SETUPAPI.SetupDiGetClassDevsW = real_getclass
    m._SETUPAPI.SetupDiDestroyDeviceInfoList = real_destroy


def enum_no_more(h, d, g, i, did):
    ctypes.set_last_error(259)   # ERROR_NO_MORE_ITEMS
    return False


m._SETUPAPI.SetupDiGetClassDevsW = lambda *a: 1
m._SETUPAPI.SetupDiDestroyDeviceInfoList = lambda h: True
m._SETUPAPI.SetupDiEnumDeviceInterfaces = enum_no_more
try:
    got = list(m._win_enumerate())
    check("ERROR_NO_MORE_ITEMS 正常结束（不抛异常）", got == [], got)
except OSError as e:
    check("ERROR_NO_MORE_ITEMS 正常结束（不抛异常）", False, e)
finally:
    m._SETUPAPI.SetupDiEnumDeviceInterfaces = real_enum_iface
    m._SETUPAPI.SetupDiGetClassDevsW = real_getclass
    m._SETUPAPI.SetupDiDestroyDeviceInfoList = real_destroy

# ------------------------------------------------------------------ P2-4 身份
print("\n### P2-4 still_matches 必须用 bus 参数并检查真实句柄")
real_attrs2 = m._win_read_attrs
real_enumerate2 = m._win_enumerate
real_bus2 = m._win_bus_of

m._win_read_attrs = lambda h: (m.NINTENDO_VID, 0x2007, None)
m._win_enumerate = lambda: iter([("\\path\\a", 1)])
m._win_bus_of = lambda d: "usb"          # 总线变了
check("总线变化 -> 拒绝",
      not m._win_still_matches("\\path\\a", 0x2007, "bluetooth", None, 1))
m._win_bus_of = lambda d: "bluetooth"
check("总线一致 + PID 一致 -> 通过",
      m._win_still_matches("\\path\\a", 0x2007, "bluetooth", None, 1))
m._win_enumerate = lambda: iter([])      # 路径消失
check("路径消失 -> 拒绝",
      not m._win_still_matches("\\path\\a", 0x2007, "bluetooth", None, 1))
m._win_enumerate = lambda: iter([("\\path\\a", 1)])
m._win_read_attrs = lambda h: (m.NINTENDO_VID, 0x2009, None)   # PID 变了
check("PID 变化 -> 拒绝",
      not m._win_still_matches("\\path\\a", 0x2007, "bluetooth", None, 1))
m._win_read_attrs = real_attrs2
m._win_enumerate = real_enumerate2
m._win_bus_of = real_bus2

print("\n### P1-4 identity() 必须返回原生句柄，而不是属性元组")
t = None
for _path, _devinst in m._win_enumerate():
    try:
        t = m._WinTransport(_path)
    except OSError:
        continue
    break
if t is None:
    print("  跳过（没有可打开的设备）")
else:
    ident = t.identity()
    check("identity() 不是元组", not isinstance(ident, tuple), type(ident).__name__)
    try:
        vid, pid, uniq = m._win_read_attrs(ident)
        check("identity() 可直接被 _win_read_attrs 使用", True,
              "VID=%04X PID=%04X" % (vid or 0, pid or 0))
    except Exception as e:
        check("identity() 可直接被 _win_read_attrs 使用", False, e)
    t.close()

print("\n### P3-8 错误码映射（错误 5 必须是 PermissionError）")
e5 = m._win_error(5, "test")
check("错误 5 -> PermissionError", isinstance(e5, PermissionError),
      type(e5).__name__)
check("错误 5 带 winerror=5", getattr(e5, "winerror", None) == 5,
      getattr(e5, "winerror", None))

print("\n### P3-9 SetupDiGetClassDevsW 失败不能当成“没有设备”")
real_getclass2 = m._SETUPAPI.SetupDiGetClassDevsW
m._SETUPAPI.SetupDiGetClassDevsW = lambda *a: m._INVALID_HANDLE_VALUE
try:
    list(m._win_enumerate())
    check("SetupDiGetClassDevsW 失败会抛异常", False, "静默返回了")
except OSError as e:
    check("SetupDiGetClassDevsW 失败会抛异常", True, e)
finally:
    m._SETUPAPI.SetupDiGetClassDevsW = real_getclass2

print("\n### P3-9 Detail 调用失败不能静默跳过")
real_enum_iface2 = m._SETUPAPI.SetupDiEnumDeviceInterfaces
real_detail = m._SETUPAPI.SetupDiGetDeviceInterfaceDetailW
real_destroy2 = m._SETUPAPI.SetupDiDestroyDeviceInfoList


def enum_one(h, d, g, i, did):
    if i == 0:
        return True
    ctypes.set_last_error(259)
    return False


def detail_real_error(*a):
    ctypes.set_last_error(87)    # ERROR_INVALID_PARAMETER，不是缓冲区不够
    return False


m._SETUPAPI.SetupDiGetClassDevsW = lambda *a: 1
m._SETUPAPI.SetupDiEnumDeviceInterfaces = enum_one
m._SETUPAPI.SetupDiGetDeviceInterfaceDetailW = detail_real_error
m._SETUPAPI.SetupDiDestroyDeviceInfoList = lambda h: True
try:
    list(m._win_enumerate())
    check("Detail 真实错误会抛异常", False, "静默跳过了")
except OSError as e:
    check("Detail 真实错误会抛异常", True, e)
finally:
    m._SETUPAPI.SetupDiEnumDeviceInterfaces = real_enum_iface2
    m._SETUPAPI.SetupDiGetDeviceInterfaceDetailW = real_detail
    m._SETUPAPI.SetupDiGetClassDevsW = real_getclass2
    m._SETUPAPI.SetupDiDestroyDeviceInfoList = real_destroy2

print("\n" + "=" * 60)
print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
if FAIL:
    for f in FAIL:
        print("  FAIL " + f)
    sys.exit(1)
print("全部通过")
