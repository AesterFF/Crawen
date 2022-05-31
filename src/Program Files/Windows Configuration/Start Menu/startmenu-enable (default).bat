@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:: Rename Start Menu
chdir /d C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy
ren StartMenuExperienceHost.old StartMenuExperienceHost.exe

:: Rename Search
chdir /d C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy
ren SearchApp.old SearchApp.exe

:: Search Icon
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f >nul 2>&1
taskkill /f /im explorer.exe
start explorer.exe

echo Start has been enabled. Please restart your computer.
pause

exit /b 0
