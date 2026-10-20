# -*- coding: utf-8 -*-
"""把源码版打成单文件 GUI exe（内嵌核心，无网络验证）。

用法：
    pip install pyinstaller
    python build_gui.py            # 打包 + 自动冒烟
    python build_gui.py --no-smoke # 只打包

产出：dist/破甲一键通GUI.exe

关键点（踩过的坑）：
  · 核心 破甲一键通.py 是以「数据文件」形式打进 exe 的（--add-data），
    PyInstaller **不会**做 AST 分析，所以核心里的 import 全都不在依赖图里。
    直接打包 → 启动报 `No module named 'platform'`（核心顶部 import platform）。
    解决：本脚本先 AST 扫描两个源文件的全部 import，逐个 --hidden-import 喂给 PyInstaller。
  · 核心文件名必须含「一键通」且落在 _MEIPASS 根目录，GUI 的 _find_core() 才认。
  · ca.pem 是官方服务器自签根证书，缺了「检查更新」会因证书校验失败而跳过。
"""
import ast
import importlib.util
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
GUI = os.path.join(REPO, "破甲GUI.py")
CORE = os.path.join(REPO, "破甲一键通.py")
ICON = os.path.join(REPO, "icon.ico")
QR = os.path.join(REPO, "donate-qr.png")
CA = os.path.join(REPO, "ca.pem")
NAME = "破甲一键通GUI"

# 三方可选：没装也能跑（webview 缺→浏览器模式），不必强制
OPTIONAL = {"webview", "tornado", "clr", "pythonnet", "pkg_resources"}


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


def main():
    for p in (GUI, CORE):
        if not os.path.isfile(p):
            print("缺少文件：%s" % p)
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
        "--console",                      # 保留控制台：日志/异常可见；要静默改成 --windowed
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
    if os.path.isfile(ICON):
        args += ["--icon", ICON]
    if os.path.isfile(QR):
        args += ["--add-data", "%s%c." % (QR, os.pathsep)]
    if os.path.isfile(CA):
        args += ["--add-data", "%s%c." % (CA, os.pathsep)]
    else:
        print("  [!] 缺 ca.pem —— 打包版「检查更新」会跳过（不影响破甲功能）")
    args.append(GUI)

    print("正在打包……")
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

    # ---- 3) 冒烟：真跑一遍，确认核心能被 import 起来 ----
    if "--no-smoke" in sys.argv:
        return 0
    print("\n--- 冒烟自检 ---")
    ok = smoke(exe)
    if not ok:
        print("\n冒烟未通过 —— exe 不可交付。")
        return 1
    print("冒烟通过。")
    return 0


def smoke(exe):
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


if __name__ == "__main__":
    sys.exit(main())
