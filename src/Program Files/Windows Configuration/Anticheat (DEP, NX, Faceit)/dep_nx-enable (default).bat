@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: ENABLE DEP
bcdedit /deletevalue nx

echo DEP has been enabled. Please restart your computer.
pause

exit /b 0
