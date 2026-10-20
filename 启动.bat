@echo off
chcp 65001 >nul
cd /d "%~dp0"

rem 破甲一键通 GUI 源码版启动器
rem 优先用 pythonw（无黑框），没有就退回 python

where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "" pythonw "%~dp0破甲GUI.py"
) else (
    where python >nul 2>&1
    if %errorlevel%==0 (
        python "%~dp0破甲GUI.py"
    ) else (
        echo.
        echo 没找到 Python。请先安装 Python 3.8+ 并勾选 "Add to PATH"。
        echo 下载：https://www.python.org/downloads/
        echo.
        pause
    )
)
