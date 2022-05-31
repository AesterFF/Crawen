@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE LANMAN WORKSTATION AND DEPENDENCIES
sc config rdbss start=demand >nul 2>&1
sc config KSecPkg start=disabled >nul 2>&1
sc config LanmanWorkstation start=disabled >nul 2>&1

:: DISABLE AUTOSHARE
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f >nul 2>&1

echo Lanman Workstation has been disabled. Please restart your computer.
pause

exit /b 0
