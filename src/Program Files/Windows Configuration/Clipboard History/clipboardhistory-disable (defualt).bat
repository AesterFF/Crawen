@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE CLIPBOARD HISTORY
for /f %%I in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /s /k /f cbdhsvc ^| find /i "cbdhsvc" ') do (
  reg add "%%I" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
)
sc config DsSvc start=disabled >nul 2>&1
reg add "HKEY_CURRENT_USER\Software\Microsoft\Clipboard" /v "EnableClipboardHistory" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f >nul 2>&1

echo Clipboard history has been disabled. Please restart your computer.
pause

exit /b 0
