@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE VPN DRIVERS
sc config PptpMiniport start=disabled >nul 2>&1
sc config RasAgileVpn start=disabled >nul 2>&1
sc config Rasl2tp start=disabled >nul 2>&1
sc config RasSstp start=disabled >nul 2>&1
sc config RasPppoe start=disabled >nul 2>&1

:: DISABLE VPN SERVICES
sc config RasMan start=disabled >nul 2>&1

echo VPN support has been disabled. Please restart your computer.
pause

exit /b 0
