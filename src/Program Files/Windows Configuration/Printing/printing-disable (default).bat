@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE PRINTING DEVICES
devcon disable "=Printer" >nul 2>&1
devcon disable "=PrintQueue" >nul 2>&1

:: DISABLE PRINTING SERVICES
sc config Spooler start=disabled >nul 2>&1

echo Printing has been disabled.
pause

exit /b 0
