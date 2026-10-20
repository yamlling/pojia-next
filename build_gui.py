# -*- coding: utf-8 -*-
"""把源码版打成单文件 GUI exe（内嵌核心，无网络验证，原生 Windows 窗口）。

用法：
    pip install pyinstaller pywebview
    python build_gui.py              # 打包（无控制台 / 原生窗口）+ 自动冒烟
    python build_gui.py --console    # 调试用：打一个带黑窗的控制台版
    python build_gui.py --no-smoke   # 只打包，不跑冒烟
    python build_gui.py --no-native  # 跳过「真开窗」验证（无桌面环境时用）

产出：dist/破甲一键通GUI.exe

关键点（踩过的坑）：
  1) 核心 破甲一键通.py 是以「数据文件」形式打进 exe 的（--add-data），
     PyInstaller **不会**做 AST 分析，所以核心里的 import 全都不在依赖图里。
     直接打包 → 启动报 `No module named 'platform'`（核心顶部 import platform）。
     解决：本脚本先 AST 扫描两个源文件的全部 import，逐个 --hidden-import 喂给 PyInstaller。
  2) 官方版是「双击直接出 Windows 窗体、没有黑窗口」= PyInstaller --windowed。
     用 --console 打出来的 exe 会先弹一个 cmd 黑窗，观感完全不同。
  3) 原生窗体靠 pywebview + pythonnet + clr_loader + WebView2 运行时。
     pywebview 走的是 .NET 动态导入（webview.platforms.winforms），
     静态分析抓不全，必须显式 --hidden-import + --collect-all，
     否则打包后 import 失败 → GUI 的 try/except 会静默退回浏览器模式
     （看起来"能跑"，但开的是浏览器标签页，不是原生窗口）。
  4) 核心文件名必须含「一键通」且落在 _MEIPASS 根目录，GUI 的 _find_core() 才认。
  5) ca.pem 是官方服务器自签根证书，缺了「检查更新」会因证书校验失败而跳过。
"""
import ast
import importlib.util
import os
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
GUI = os.path.join(REPO, "破甲GUI.py")
CORE = os.path.join(REPO, "破甲一键通.py")
ICON = os.path.join(REPO, "icon.ico")
QR = os.path.join(REPO, "donate-qr.png")
CA = os.path.join(REPO, "ca.pem")
NAME = "破甲一键通GUI"

# 原生窗口必备的三件套（pywebview 的后端是 .NET，PyInstaller 看不全）
# webview 缺失 → GUI 会退回浏览器模式；这里装不到就明确报出来，不静默降级。
WEBVIEW_PKGS = ("webview", "pythonnet", "clr_loader")

# 这些模块静态分析会扫到，但 Windows 上永远用不到，显式排掉（减小体积 + 少一堆 warning）
EXCLUDE_MODULES = (
    # pywebview 的其它平台后端（Windows 只用 winforms + edgechromium）
    "webview.platforms.gtk",
    "webview.platforms.qt",
    "webview.platforms.cocoa",
    "webview.platforms.cef",
    "webview.platforms.android",
    "gi",
    "qtpy",
    "objc",
    # 环境里的科学计算/图像/加密大件：本程序一行都没用到，
    # 但 conda 环境里装了它们，PyInstaller 的 hook 会顺带把 MKL 一起拖进来
    # （实测单独 numpy 就能把 exe 从 13MB 撑到 250MB+）。
    "numpy",
    "scipy",
    "pandas",
    "matplotlib",
    "PIL",
    "Pillow",
    "cryptography",
    "yaml",
    "psutil",
    "win32",
    "pythoncom",
    "pywintypes",
    "tkinter",
)


def scan_imports(paths):
    """AST 扫描出所有顶层 import 的模块名（含函数体里的延迟导入）。"""
    mods = set()
    for p in paths:
        try:
            tree = ast.parse(open(p, encoding="utf-8").read())
        except SyntaxError as e:
            print("  [!] %s 语法错误，跳过扫描：%s" % (os.path.basename(p), e))
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    mods.add(a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom):
                if getattr(n, "level", 0) == 0 and n.module:
                    mods.add(n.module.split(".")[0])
    return mods


def resolvable(mod):
    """当前解释器里能不能 import 到（不能就别喂给 PyInstaller，否则刷一堆 warning）。"""
    if mod in sys.builtin_module_names:
        return True
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def read_gui_version():
    """从 GUI 源码抠 DISPLAY_VER，用于窗口标题验证。"""
    import re
    try:
        txt = open(GUI, encoding="utf-8").read()
    except OSError:
        return None
    m = re.search(r'^DISPLAY_VER\s*=\s*"([^"]+)"', txt, re.M)
    return m.group(1) if m else None


def pe_subsystem(exe):
    """读 PE 头 Subsystem：2=GUI（无控制台），3=Console（有黑窗）。"""
    try:
        with open(exe, "rb") as f:
            if f.read(2) != b"MZ":
                return None
            f.seek(0x3C)
            off = struct.unpack("<I", f.read(4))[0]
            f.seek(off)
            if f.read(4) != b"PE\0\0":
                return None
            f.seek(off + 0x18)          # OptionalHeader 起点（PE32 / PE32+ 同偏移）
            f.seek(off + 0x18 + 68)     # Subsystem：PE32 与 PE32+ 都在 +68
            return struct.unpack("<H", f.read(2))[0]
    except OSError:
        return None


def main():
    for p in (GUI, CORE):
        if not os.path.isfile(p):
            print("缺少文件：%s" % p)
            return 1

    want_console = "--console" in sys.argv

    # ---- 0) 原生窗口依赖预检（缺了就别打，打了也是浏览器模式）----
    missing = [m for m in WEBVIEW_PKGS if not resolvable(m)]
    if missing:
        print("缺少原生窗口依赖：%s" % ", ".join(missing))
        print("先装：%s -m pip install -i https://pypi.org/simple pywebview" % sys.executable)
        return 1

    # ---- 1) 收集依赖（核心是 data 文件，PyInstaller 看不见它里面的 import）----
    mods = scan_imports([GUI, CORE])
    hidden, skipped = [], []
    for m in sorted(mods):
        if m in ("sys", "os", "__future__"):
            continue
        if resolvable(m):
            hidden.append(m)
        else:
            skipped.append(m)
    print("扫描到 %d 个 import，可打入 %d 个" % (len(mods), len(hidden)))
    if skipped:
        print("  跳过（当前环境装不到）：%s" % ", ".join(skipped))

    # ---- 2) 组装 PyInstaller 参数 ----
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile",
        # 官方版观感：无控制台 + 原生窗口。--console 只在调试时用
        "--console" if want_console else "--windowed",
        "--noupx",
        "--name", NAME,
        "--distpath", os.path.join(REPO, "dist"),
        "--workpath", os.path.join(REPO, "_build", "work"),
        "--specpath", os.path.join(REPO, "_build", "spec"),
        # 核心跟着走：运行时解压到 _MEIPASS 根目录，_find_core() 会命中
        "--add-data", "%s%c." % (CORE, os.pathsep),
    ]
    for m in hidden:
        args += ["--hidden-import", m]
    for m in EXCLUDE_MODULES:
        args += ["--exclude-module", m]

    # ---- 2b) 原生窗口：显式补齐 .NET 后端（pywebview 静态分析抓不全）----
    for m in ("webview.platforms.winforms", "webview.platforms.edgechromium",
              "webview.platforms.win32", "webview.guilib", "clr", "pythonnet",
              "clr_loader", "clr_loader.ffi", "cffi", "_cffi_backend"):
        args += ["--hidden-import", m]
    # collect-all 把 data / binaries / submodules 一并收进来：
    #   webview    → lib/WebView2Loader.dll、js/ 注入脚本、__pyinstaller hook
    #   pythonnet  → runtime/Python.Runtime.dll
    #   clr_loader → ffi/dlls/amd64/ClrLoader.dll
    for pkg in WEBVIEW_PKGS:
        args += ["--collect-all", pkg]

    if os.path.isfile(ICON):
        args += ["--icon", ICON]
    else:
        print("  [!] 缺 icon.ico —— exe 用默认图标")
    if os.path.isfile(QR):
        args += ["--add-data", "%s%c." % (QR, os.pathsep)]
    if os.path.isfile(CA):
        args += ["--add-data", "%s%c." % (CA, os.pathsep)]
    else:
        print("  [!] 缺 ca.pem —— 打包版「检查更新」会跳过（不影响破甲功能）")
    args.append(GUI)

    print("正在打包（%s / %s）……" % ("控制台版" if want_console else "窗口版",
                                     "onedir" if "--onedir" in sys.argv else "onefile"))
    r = subprocess.run(args, cwd=REPO)
    if r.returncode != 0:
        print("PyInstaller 失败，exit %s" % r.returncode)
        return r.returncode

    exe = os.path.join(REPO, "dist", NAME + ".exe")
    if not os.path.isfile(exe):
        cands = [f for f in os.listdir(os.path.join(REPO, "dist"))
                 if f.lower().endswith(".exe")]
        if len(cands) == 1:
            exe = os.path.join(REPO, "dist", cands[0])
        else:
            print("没找到产出：%s" % exe)
            return 1
    print("\n已产出：%s（%.1f MB）" % (exe, os.path.getsize(exe) / 1048576))

    # ---- 3) PE 子系统自检：确认没有黑窗 ----
    sub = pe_subsystem(exe)
    sub_name = {2: "GUI（无控制台）", 3: "Console（有黑窗）"}.get(sub, "未知(%s)" % sub)
    print("PE Subsystem     -> %s" % sub_name)
    if not want_console and sub != 2:
        print("  [FAIL] 打出来还是控制台子系统，双击会有黑窗")
        return 1

    if "--no-smoke" in sys.argv:
        return 0

    # ---- 4) 冒烟一：无头跑，确认核心真的加载（走 HTTP API）----
    print("\n--- 冒烟①：核心加载 ---")
    if not smoke_core(exe):
        print("\n冒烟未通过 —— exe 不可交付。")
        return 1

    # ---- 5) 冒烟二：真开窗，确认原生窗口出来了（不是浏览器标签页）----
    if "--no-native" not in sys.argv:
        print("\n--- 冒烟②：原生窗口 ---")
        if not smoke_window(exe):
            print("\n原生窗口没验证通过 —— 双击后可能退回浏览器模式。")
            return 1

    print("\n全部通过。")
    return 0


def smoke_core(exe):
    """启动 exe（无头），轮询本地 API 判断核心是否真的加载成功。"""
    import json
    import socket
    import time
    import urllib.request

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    proc = subprocess.Popen([exe, "--no-browser"], cwd=os.path.dirname(exe),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=env)
    url = None
    try:
        # 服务端口从 8317 起递增，逐个探
        for _ in range(40):
            time.sleep(0.5)
            if proc.poll() is not None:
                break
            for port in range(8317, 8340):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        url = "http://127.0.0.1:%d" % port
                        break
                except OSError:
                    continue
            if url:
                break
        if not url:
            print("  [FAIL] 界面服务没起来")
            out = b""
            try:
                out = proc.communicate(timeout=5)[0] or b""
            except Exception:
                pass
            if out:
                print("  exe 输出：" + out.decode("utf-8", "replace")[:800])
            return False

        def get(path):
            with urllib.request.urlopen(url + path, timeout=8) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))

        st = {}
        for _ in range(30):               # 核心在后台线程加载，最多等 15 秒
            st = get("/api/cloud/state")
            if st.get("state") != "loading":
                break
            time.sleep(0.5)

        print("  /api/cloud/state -> %s" % json.dumps(st, ensure_ascii=False))
        if st.get("mode") != "local":
            print("  [FAIL] 不是本地核心模式")
            return False

        info = get("/api/state")
        tg = info.get("targets") or []
        print("  /api/state       -> ver %s，%d 个目标" % (info.get("version"), len(tg)))
        if not tg:
            print("  [FAIL] 目标列表为空，核心没真正起来")
            return False

        log = get("/api/log")
        lines = [l for _, l in log.get("lines", [])]
        head = lines[0] if lines else ""
        print("  启动日志         -> %s" % head)
        if "核心已加载" not in head:
            print("  [FAIL] 核心未加载成功")
            for l in lines[:10]:
                print("     " + l)
            return False
        return True
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


def smoke_window(exe):
    """正常启动（不带 --no-browser），用 Win32 找窗口标题 —— 有窗口才算原生窗口跑起来了。

    同时也盯一眼启动日志：出现「退回浏览器模式」就直接判失败。
    """
    import ctypes
    import json
    import socket
    import time
    import urllib.request

    user32 = ctypes.windll.user32
    ver = read_gui_version()
    title = "破甲一键通 v%s" % ver if ver else None
    if not title:
        print("  [SKIP] 读不到 DISPLAY_VER，无法按标题找窗口")
        return True

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    proc = subprocess.Popen([exe], cwd=os.path.dirname(exe), env=env)
    found = False
    url = None
    try:
        t0 = time.time()
        while time.time() - t0 < 60:
            time.sleep(0.5)
            if proc.poll() is not None:
                print("  [FAIL] exe 自己退了（exit %s）" % proc.returncode)
                return False
            if user32.FindWindowW(None, title):
                found = True
                print("  找到窗口         -> 「%s」" % title)
                break
        if not found:
            print("  [FAIL] 60 秒内没出现标题为「%s」的窗口" % title)
            return False

        # 顺手确认：窗口起来了，说明没走浏览器兜底；再从日志复核一遍
        for port in range(8317, 8340):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    url = "http://127.0.0.1:%d" % port
                    break
            except OSError:
                continue
        if url:
            try:
                with urllib.request.urlopen(url + "/api/log", timeout=5) as resp:
                    log = json.loads(resp.read().decode("utf-8", "replace"))
                lines = [l for _, l in log.get("lines", [])]
                bad = [l for l in lines
                       if "退回浏览器模式" in l or "已切换浏览器模式" in l]
                if bad:
                    print("  [FAIL] 日志显示退回了浏览器模式：%s" % bad[0])
                    return False
            except Exception:
                pass
        return True
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
