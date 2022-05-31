@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: ENABLE WORKSTATION
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\rdbss" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\KSecPkg" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb20" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\srv2" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
dism /Online /Enable-Feature /FeatureName:SmbDirect /norestart 

sc config eventlog start=auto >nul 2>&1

:: ENABLE SERVICES
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NlaSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\lmhosts" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\netman" /v "Start" /t REG_DWORD /d "3" /f


echo Network discovery has been enabled. Please restart your computer.
pause

exit /b 0
