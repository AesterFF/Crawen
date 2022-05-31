@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE INTERNET EXPLORER
dism /Online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64 /norestart

echo Internet Explorer has been disabled. Please restart your computer.
pause

exit /b 0
