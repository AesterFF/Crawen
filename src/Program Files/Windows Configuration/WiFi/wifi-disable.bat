@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE WIFI DRIVERS
sc config vwififlt start=demand >nul 2>&1

:: DISABLE WIFI SERVICES
sc config WlanSvc start=disabled >nul 2>&1

echo WiFi services have been disabled. Please restart your computer.
pause

exit /b 0
