@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE DEP
bcdedit /set nx AlwaysOff

echo DEP has been disabled. Please restart your computer.
pause

exit /b 0
