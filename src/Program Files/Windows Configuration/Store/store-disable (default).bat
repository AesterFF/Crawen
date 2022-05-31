@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE MICROSOFT STORE 
:: Disable the option for Windows Store in the "Open With" dialog
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f >nul 2>&1

:: Block Access to Windows Store
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d "1" /f >nul 2>&1
sc config InstallService start=disabled >nul 2>&1

:: Insufficent permissions to disable
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

sc config mpssvc start=disabled >nul 2>&1
sc config wlidsvc start=disabled >nul 2>&1
sc config AppXSvc start=disabled >nul 2>&1
sc config BFE start=disabled >nul 2>&1
sc config TokenBroker start=disabled >nul 2>&1 
sc config LicenseManager start=disabled >nul 2>&1
sc config AppXSVC start=disabled >nul 2>&1
sc config ClipSVC start=disabled >nul 2>&1
sc config FileInfo start=disabled >nul 2>&1
sc config FileCrypt start=disabled >nul 2>&1

echo Store has been disabled. Please restart your computer.
pause

exit /b 0
