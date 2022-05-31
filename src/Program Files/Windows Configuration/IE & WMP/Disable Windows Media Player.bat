@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: DISABLE WMP
dism /Online /Disable-Feature /FeatureName:WindowsMediaPlayer /norestart

echo WMP has been disabled. Please restart your computer.
pause

exit /b 0
