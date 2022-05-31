@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!
echp NOTE: DISABLE ONLY IF YOU DON'T USE STORE!
timeout /t 5 & cls

:: DISABLE FIREWALL
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

echo Firewall has been disabled. Please restart your computer.
pause

exit /b 0
