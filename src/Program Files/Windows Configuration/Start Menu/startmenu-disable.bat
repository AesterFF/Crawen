@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
echo This Script has to be run as administrator, otherwise it won't work properly!

:restartStart
:: Rename Start Menu
chdir /d C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy

taskkill /F /IM StartMenuExperienceHost*
ren StartMenuExperienceHost.exe StartMenuExperienceHost.old

:: Loop if it fails to rename the first time
if exist "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" goto restartStart

:: Rename Search
chdir /d C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy

:restartSearch
taskkill /F /IM SearchApp*  >nul 2>nul
ren SearchApp.exe SearchApp.old

:: Loop if it fails to rename the first time
if exist "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" goto restartSearch

:: Search Icon
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >nul 2>&1

taskkill /f /im explorer.exe
start explorer.exe

echo Start has been disabled. Please restart your computer.
pause

exit /b 0
