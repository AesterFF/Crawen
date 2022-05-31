@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE BLUETOOTH DEVICES
devcon disable BTH* >nul 2>&1
devcon disable =Bluetooth >nul 2>&1

:: DISABLE BLUETOOTH SERVICES
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config BluetoothUserService start=disabled >nul 2>&1
sc config BTAGService start=disabled >nul 2>&1
sc config BthAvctpSvc start=disabled >nul 2>&1
sc config bthserv start=disabled >nul 2>&1

echo Bluetooth services have been disabled. Please restart your computer.
pause

exit /b 0
