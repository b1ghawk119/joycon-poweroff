# joycon-poweroff

**Turn off Nintendo Switch Joy-Con and Pro Controllers completely — back to factory shipment state — so they stop draining their battery in storage.**

Zero-dependency Python 3. Talks to the HID device directly — `/dev/hidraw` on Linux, SetupAPI via `ctypes` on Windows. No `hidapi`, no compiling, no touching system directories, no driver installation.

[中文说明](README.zh-CN.md) · [Protocol reference](#what-it-actually-does) · [Safety](#safety)

---

## The problem

Nintendo gives you no way to turn a Switch controller off. Pressing the sync button or letting it idle only puts it into a sleep mode that keeps draining the battery — a fully charged Joy-Con goes flat in about a week or two of storage.

The controllers *can* be genuinely powered down over Bluetooth, using a low-power state the firmware reserves for shipping. This script does exactly that, and verifies the write actually landed.

After a successful run the controller:

- consumes almost nothing (measured battery life in storage is **2–3 years**, not weeks)
- cannot be woken by pressing buttons
- has its pairing information erased

To use it again, plug it into a Switch with a USB cable, or hold the sync button to pair it afresh.

---

## Quick start

Both platforms use the same single file. Pair the controller over Bluetooth first — hold the small round sync button (next to the player LEDs) until the LEDs flash, then finish pairing in your system's Bluetooth settings. **USB will NOT work** — see [Safety](#safety).

### Linux

```bash
# 1. Grab the script (it is a single file)
curl -O https://raw.githubusercontent.com/b1ghawk119/joycon-poweroff/main/joycon-poweroff.py

# 2. Check the controller is detected
sudo python3 joycon-poweroff.py --list

# 3. Preview the exact packets that would be sent — nothing is transmitted
sudo python3 joycon-poweroff.py --dry-run

# 4. Do it
sudo python3 joycon-poweroff.py
```

### Windows

```powershell
# 1. Grab the script
curl.exe -O https://raw.githubusercontent.com/b1ghawk119/joycon-poweroff/main/joycon-poweroff.py

# 2. Check the controller is detected (no admin rights needed)
py -3 joycon-poweroff.py --list

# 3. Preview the exact packets that would be sent — nothing is transmitted
py -3 joycon-poweroff.py --dry-run

# 4. Do it
py -3 joycon-poweroff.py
```

> On Windows use `py -3` (the Python launcher) rather than `python`, so the script runs under the interpreter you expect. `python.exe` from the Microsoft Store also works.

A successful run looks like this:

```
目标：Joy-Con (R)  (/dev/hidraw3, bluetooth)

[1/6] 切 Simple HID 输入模式
[2/6] 点亮 4 个灯
[3/6] 清配对信息 (SPI 0x2000)
[4/6] 置装运低功耗标志 (SPI 0x5000 = 0x01)
[5/6] 回读校验
      SPI 0x5000 = 0x01  ✓
      SPI 0x2000 前 2 个配对槽已清除  ✓
      （只抽查了前 2 个槽，更靠后的记录没检查）
      0x05 主机列表状态 = 0x00（参考值，不作判据）
[6/6] 断开并断电

完成，手柄应已断电。
唤醒：插 USB 到 Switch，或长按 sync 键重新配对。
```

> Script output is in Chinese. See [Reading the output](#reading-the-output) for a translation of the important lines.

---

## Usage examples

### List connected controllers

```bash
$ sudo python3 joycon-poweroff.py --list
Joy-Con (L)            /dev/hidraw3  (bluetooth)
Joy-Con (R)            /dev/hidraw4  (bluetooth)
Pro Controller         /dev/hidraw5  (bluetooth)
```

It also reports the bus, so you can tell at a glance whether a controller is on Bluetooth or USB. Controllers on USB are flagged `[不支持]` (unsupported) and refused.

### Preview without sending anything

```bash
$ sudo python3 joycon-poweroff.py --dry-run
```

Prints every packet it *would* send, byte by byte, and exits without writing. Use this to confirm the sequence before committing:

```
[3/6] 清配对信息 (SPI 0x2000)
      > 01 02 00 01 40 40 00 01 40 40 07
[4/6] 置装运低功耗标志 (SPI 0x5000 = 0x01)
      > 01 03 00 01 40 40 00 01 40 40 08 01
[5/6] 回读校验
      > 01 04 00 01 40 40 00 01 40 40 10 00 50 00 00 01
      > 01 05 00 01 40 40 00 01 40 40 10 00 20 00 00 01
      > 01 06 00 01 40 40 00 01 40 40 10 26 20 00 00 01
      > 01 07 00 01 40 40 00 01 40 40 05
      (dry-run，不校验)
[6/6] 断开并断电
      > 01 08 00 01 40 40 00 01 40 40 06 00
```

### Turn off one controller

```bash
sudo python3 joycon-poweroff.py
```

Walks you through it interactively, including a confirmation step that makes the controller's four LEDs flash together. **Watch the LEDs** — if all four do not flash in sync, you are not on Bluetooth and should cancel.

### Several controllers connected at once

The script asks which one to target:

```bash
$ sudo python3 joycon-poweroff.py
检测到多个 Nintendo 手柄：
  [1] Joy-Con (L)            /dev/hidraw3  (bluetooth)
  [2] Joy-Con (R)            /dev/hidraw4  (bluetooth)
选择要关闭的手柄 [1-3]: 2

目标：Joy-Con (R)  (/dev/hidraw4, bluetooth)
...
```

Run it once per controller to turn off a whole set.

### Unattended / scripted use

`--yes` skips every prompt. It refuses to guess when more than one controller is connected, so it is safe to put in a script that runs with exactly one controller attached:

```bash
sudo python3 joycon-poweroff.py --yes
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0`  | Controller powered off, or `--list` / `--dry-run` completed |
| `1`  | Aborted, or the goal was not reached. The reason is printed. **This does not guarantee nothing changed** — an interruption or an ambiguous write result after sending `0x06` also produces exit code 1. |

### Steam Deck

Works in Desktop Mode. The script needs raw HID access, so run it with `sudo`:

```bash
# In Desktop Mode, open Konsole
curl -O https://raw.githubusercontent.com/b1ghawk119/joycon-poweroff/main/joycon-poweroff.py
sudo python3 joycon-poweroff.py
```

There is nothing to install and nothing to uninstall — deleting the file removes it completely.

---

## What it actually does

Each command is a 64-byte HID output report:

```
buf[0]     = 0x01        report ID
buf[1]     = packet counter 0..15
buf[2..9]  = rumble data (fixed)
buf[10]    = subcommand
buf[11..]  = arguments
```

The script sends this sequence, checking the reply to each step before moving on:

| # | Subcommand | Argument | Purpose |
|---|-----------|----------|---------|
| 1 | `0x03` Set input report mode | `0x3F` | Switch to Simple HID mode to cut read noise |
| 2 | `0x30` Set player lights | `0xF0` | Flash all four LEDs — **your manual check that this is a Bluetooth link** |
| 3 | `0x07` Reset pairing info | — | Initialize the `0x2000` SPI section (erases pairing data) |
| 4 | `0x08` Set shipment low power state | `0x01` | Write `0x01` at SPI `0x5000` — the low-power flag |
| 5 | `0x10` SPI flash read | `0x5000`, len 1 | Read back: must be `0x01` |
| 5 | `0x10` SPI flash read | `0x2000`, len 1 | Read back the pairing magic: must no longer be `0x95` |
| 5 | `0x10` SPI flash read | `0x2026`, len 1 | Same check for the second pairing slot |
| 5 | `0x05` Get page list state | — | Query the in-memory host list (printed for reference only) |
| 6 | `0x06` Set HCI state | `0x00` | Disconnect → the controller enters HID OFF and powers down |

**Why `0x07` and `0x08` are both required.** They are not redundant — each covers a different way the controller can be woken:

- `0x08 01` alone sets the low-power flag, but the firmware only refuses to wake on the *easy-to-press* buttons. As long as pairing data exists, a long press on certain buttons still wakes it.
- `0x07` alone erases pairing, but with the low-power flag unset the controller stays in ordinary sleep and still goes flat in a week or two.
- Together, the controller drops into HID OFF and cannot be woken by buttons at all. That is the real factory state.

**Why `0x06` matters.** The low-power flag only takes effect *when the link drops*. Sending `0x06 00` drops it immediately, so the controller powers down right away instead of waiting for the host to disconnect.

Protocol details are documented in the [Nintendo Switch reverse-engineering notes](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering).

---

## Reading the output

The script prints in Chinese. The lines that matter:

| Output | Meaning |
|--------|---------|
| `完成，手柄应已断电。` | **Success** — the controller has powered off |
| `SPI 0x5000 = 0x01  ✓` | The low-power flag was read back and confirmed |
| `SPI 0x2000 前 2 个配对槽已清除  ✓` | Pairing slots verified erased |
| `已中止，未发送断电命令。` | **Aborted** — no power-off was sent. The controller may still have been modified: read the follow-up lines, which distinguish commands that were acknowledged from ones that may have been sent but never confirmed |
| `✗ SPI 0x5000 = ...，不是 0x01。` | Verification failed; the flag did not land |
| `⚠ 未能确认手柄已恢复标准输入模式。` | Could not confirm input mode was restored — **reconnect the controller**, or buttons may not respond |
| `✗ 这不是蓝牙连接（usb）。` | Not a Bluetooth link; refused, because USB cannot power the controller off |

---

## Requirements

- **Linux** with `/dev/hidraw` — any modern distro, Steam Deck included. Needs root, or a user with read/write access to the controller's `/dev/hidraw*` node.
- **Windows 10 or 11** — no admin rights, no driver installation. Uses `setupapi.dll`, `hid.dll`, `cfgmgr32.dll` and `kernel32.dll`, all of which ship with Windows.
- **Python 3.7 or newer** — nothing else.

No `pip install`, no build step, no system packages.

---

## Safety

**This script writes to your controller's SPI flash.** The operation is the same one Nintendo performs at the factory, and it is safe when used correctly — but a mistake can brick a controller. Use at your own risk.

The script is built to fail safe:

- **Every step is verified before the next one runs.** `0x07` and `0x08` must return an `0x80` acknowledgement; the SPI readbacks must match on acknowledgement byte, echoed address, *and* returned length. If any check fails, the script stops **without** sending `0x06`. Note what that does and does not mean: a failed *readback* does not prove an earlier write did not land, so an abort can still leave the controller modified. The script's closing lines tell you which commands were acknowledged and which may have been sent unconfirmed, rather than claiming nothing happened.
- **It refuses USB, unconditionally.** `0x06` does nothing over USB and the low-power flag never triggers, so the script detects the bus and declines **before sending anything at all** — no `0x03`, no `0x07`, no `0x08`. There is no override, in any mode. Continuing on USB would only erase pairing data and set a flag that can never take effect, which is worse than doing nothing.
- **It refuses unknown devices.** Only the five known controller product IDs are accepted. A device that merely claims Nintendo's vendor ID is skipped.
- **It re-checks device identity before writing.** Device nodes get reused — `/dev/hidrawN` numbers are recycled, and a controller can disconnect between detection and opening. The script confirms the opened device is still the one it enumerated, rather than writing to whatever took its place.
- **It restores input mode on every exit path.** Simple HID mode (`0x3F`) is not understood by the standard HID drivers, so a controller left in it looks connected but stops responding to buttons. The script switches back to standard mode on cancellation, on error, and on Ctrl-C.
- **It tells you what actually happened.** On failure it distinguishes commands that were acknowledged from ones that may have been sent but never confirmed, rather than claiming success.

Two things worth knowing before you start:

1. **Watch the LEDs at step 2.** All four must flash together. If they do not, you are not on Bluetooth — cancel.
2. **A Switch undoes this.** Every time the console connects, it sends `0x08 00` and clears the flag. Once a controller is paired to a Switch again, it goes back to normal sleep behaviour.

---

## Known limitations

- **Pairing slots are spot-checked, not exhaustively read.** The `0x2000` section holds pairing records in a repeating `0x26`-byte layout of unknown length, and the protocol caps a single SPI read at `0x1D` bytes — reading the whole 4 KB section would take roughly 141 round trips. The script checks the first two slots (which covers the current pairing and the previous one) and says so in its output. A record buried deeper would not be detected.
- **The `0x05` host-list query is informational only.** It is printed but never gates shutdown, because no documentation establishes whether `0x07` clears the in-memory list as well as the flash. Treating it as a gate would risk false aborts on real hardware.
- **Bluetooth only.** USB is detected and refused, not worked around.
- **The Windows backend is experimental and has never been tested against a real controller.** It is written against Microsoft's documented SetupAPI / HID contracts, its overlapped-I/O handling is covered by 71 mocked assertions, and the discovery/identity path has been exercised end-to-end on real hardware (with a non-controller device). But no Joy-Con, Pro Controller or other supported controller has ever been connected on Windows. Concretely unverified: real enumeration and parent grouping, report lengths, serial availability, successful Bluetooth writes and replies, SPI readback, physical power-off, and recovery. Run `--dry-run` and watch the LEDs the first time. The Linux backend is the better-tested path.
- **Linux and Windows only.** macOS exposes HID through IOKit, which this script does not implement. WSL2 cannot see a controller paired to Windows — the Windows Bluetooth stack is not visible from inside the WSL2 VM. Run the script with Windows Python instead, which works from a WSL shell too:
  ```bash
  py.exe -3 "$(wslpath -w ./joycon-poweroff.py)" --list
  ```
- **Not tested on hardware by the author of this README.** The protocol handling is checked byte-by-byte against the published reverse-engineering notes, and the logic is covered by an automated test suite — but you should still run `--dry-run` and watch the LEDs the first time.

---

## Troubleshooting

**`没找到 Nintendo 手柄。` (No controller found)**
- Make sure the controller is connected over Bluetooth, not USB.
- Run `--list` to see what is actually detected.
- If `--list` shows your controller but a normal run does not, the controller may have disconnected between detection and opening — reconnect and retry.

**`没有权限打开 /dev/hidrawN` (Permission denied)**
- Run with `sudo`. Alternatively, add a udev rule granting your user access to the controller's hidraw node.

**The LEDs do not flash together at step 2**
- You are not on Bluetooth. Cancel and pair properly. This check exists precisely to catch this.

**`✗ 这不是蓝牙连接（usb）。` (Not a Bluetooth connection)**
- The script found the controller on the USB bus and refused **before sending anything** — no `0x03`, no `0x07`, no `0x08`. This refusal happens before any command, so the controller really is untouched here. Unplug it and connect over Bluetooth; USB cannot power a controller off.
- This refusal is intentional and has no override. On USB the script could only erase pairing data and set a low-power flag that never takes effect, leaving the controller worse off than before.

**Buttons stop responding after a cancelled run**
- The script should have restored standard input mode automatically. If it warns that it could not, disconnect and reconnect the controller — that resets the mode.

**The controller came back on by itself**
- Something reconnected to it. A Switch clears the low-power flag on every connection. Disconnect it from everything, then run the script again.

---

## Uninstall

```bash
rm joycon-poweroff.py
```

That is the whole program. Nothing was installed, no configuration was written, no system files were touched.

---

## License

MIT — see [LICENSE](LICENSE).
