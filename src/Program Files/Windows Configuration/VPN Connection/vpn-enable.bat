@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: ENABLE VPN DRIVERS
sc config PptpMiniport start=demand >nul 2>&1
sc config RasAgileVpn start=demand >nul 2>&1
sc config Rasl2tp start=demand >nul 2>&1
sc config RasSstp start=demand >nul 2>&1
sc config RasPppoe start=demand >nul 2>&1

:: ENABLE VPN SERVICES
sc config RasMan start=auto >nul 2>&1

echo VPN support has been enabled. Please restart your computer.
pause

exit /b 0
