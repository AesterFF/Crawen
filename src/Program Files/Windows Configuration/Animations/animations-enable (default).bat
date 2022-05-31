@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: ENABLE ANIMATIONS
reg delete "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "1" /f>nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9e3e078012000000" /f >nul 2>&1

echo Animations have been enabled. Please restart your computer.
pause

exit /b 0
