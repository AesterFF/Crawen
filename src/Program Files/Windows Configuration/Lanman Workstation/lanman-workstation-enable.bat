@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: ENABLE LANMAN WORKSTATION AND DEPENDENCIES
sc config rdbss start=system >nul 2>&1
sc config KSecPkg start=boot >nul 2>&1
sc config LanmanWorkstation start=auto >nul 2>&1

:: ENABLE AUTOSHARE
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "1" /f >nul 2>&1

echo Lanman Workstation has been enabled. Please restart your computer.
pause

exit /b 0
