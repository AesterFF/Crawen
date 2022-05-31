@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: ENABLE WIFI DRIVERS
sc config vwififlt start=system >nul 2>&1
sc start vwififlt >nul 2>&1

:: ENABLE WIFI SERVICES
sc config WlanSvc start=auto >nul 2>&1
sc start WlanSvc >nul 2>&1

echo WiFi services have been enabled.
pause

exit /b 0
