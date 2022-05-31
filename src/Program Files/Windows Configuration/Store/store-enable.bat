@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: ENABLE MICROSOFT STORE
:: Enable the option for Windows Store in the "Open With" dialog
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "0" /f >nul 2>&1

:: Allow Access to Windows Store
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d "0" /f >nul 2>&1
sc config InstallService start=demand >nul 2>&1

:: Insufficent permissions to enable through SC
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1

sc config mpssvc start=auto >nul 2>&1
sc config wlidsvc start=demand >nul 2>&1
sc config AppXSvc start=demand >nul 2>&1
sc config BFE start=auto >nul 2>&1
sc config TokenBroker start=demand >nul 2>&1
sc config LicenseManager start=demand >nul 2>&1
sc config wuauserv start=demand >nul 2>&1
sc config AppXSVC start=demand >nul 2>&1
sc config ClipSVC start=demand >nul 2>&1
sc config FileInfo start=boot >nul 2>&1
sc config FileCrypt start=system >nul 2>&1

echo Store and has been disabled. Please restart your computer.
pause

exit /b 0
