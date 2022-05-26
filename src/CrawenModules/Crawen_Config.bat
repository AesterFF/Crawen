@echo off
SETLOCAL EnableDelayedExpansion

>nul 2>nul "%WinDir%\System32\cacls.exe" "%WinDir%\System32\config\system"

set version=0.2.0
TITLE Crawen Configurator %version%
wscript %windir%\CrawenModules\fullscreen.vbs

:: set variables
set scriptlog=%windir%\CrawenModules\logs\Install.log
set configfile=%windir%\CrawenModules\config.bat
set QN=14
set VS_VER=0.60.0

:CREDITS
echo CREDITS
echo.
echo Special thanks to Amit, Phlegm, Zusier and Artanis
echo.
echo Also to EchoX, SHDW, Melody, imribiy
echo.
pause

:START
cls
echo FIRST RUN
echo.
echo In this App you can configure and customize CrawernOS
echo.
echo Read questions and answer them, you will get best results.
echo.
echo If you need support, join the CrawenOS Discord - discord.gg/crawenos.
echo.
pause

:CONNECTION
cls
echo [1/%QN%] Which type of connection will you be using?
echo.
echo [1] Ethernet (Cable)
echo. 
echo [2] Wi-Fi (Wireless)
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set CONNECTION_TYPE=WIFI
cls & goto GRAPHICS
)
if errorlevel 1 (
>> %configfile% echo set CONNECTION_TYPE=ETHERNET
cls & goto GRAPHICS
)


:GRAPHICS
cls
echo [2/%QN%] What GPU combination do you have in your system?
echo.
echo [1] AMD GPU
echo. 
echo [2] NVIDIA GPU
echo.
echo [3] INTEL or AMD iGPU
echo.
choice /c:123 /n >NUL 2>&1
if errorlevel 3 (
>> %configfile% echo set GRAPHICS=INTEL
cls & goto LAPTOP
)
if errorlevel 2 (
>> %configfile% echo set GRAPHICS=NVIDIA
cls & goto NVIDIADRIVER
)
if errorlevel 1 (
>> %configfile% echo set GRAPHICS=AMD
cls & goto AMDDRIVER
)

:AMDDRIVER
echo.
echo Here you can install AMD Drivers
echo.
echo 22.5.1 
echo 22.5.PR [RX 5000 / 6000] 
echo 21.10.2
echo.
set /p AMDDRIVER="Enter what driver you would like to use: "
set AMDDRIVER=%AMDDRIVER: =%

if "%AMDDRIVER%" EQU " =" cls & goto INVALID_AMD
if "%AMDDRIVER%" EQU "=" cls & goto INVALID_AMD

for %%i in (skip SKIP 22.5.1 22.5.PR 21.10.2) do (
    if %AMDDRIVER% EQU %%i (
>> %configfile% echo set AMDDRIVER=%AMDDRIVER%
cls & goto RADEON_SOFTWARE
)
)

:INVALID_AMD
cls
echo Invalid input
echo.
goto AMDDRIVER

:RADEON_SOFTWARE
cls
echo Do you want to install Radeon Software Panel?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set RADEON_SOFTWARE=FALSE
cls & goto LAPTOP
)
if errorlevel 1 (
>> %configfile% echo set RADEON_SOFTWARE=TRUE
cls & goto LAPTOP
)

:NVIDIADRIVER
echo.
echo Available NVIDIA Drivers:
echo.
echo 441.41
echo 442.74
echo 456.71
echo 457.30
echo 457.51
echo 461.92
echo 466.11
echo 472.12
echo 512.77
echo.
set /p NVIDIADRIVER="Enter what driver you would like to use: "
set NVIDIADRIVER=%NVIDIADRIVER: =%

if "%NVIDIADRIVER%" EQU " =" cls & goto INVALID_NVIDIA
if "%NVIDIADRIVER%" EQU "=" cls & goto INVALID_NVIDIA

for %%i in (skip SKIP 441.41 442.74 456.71 457.30 457.51 461.92 466.11 472.12 512.77) do (
    if %NVIDIADRIVER% EQU %%i (
>> %configfile% echo set NVIDIADRIVER=%NVIDIADRIVER%
cls & goto LAPTOP
)
)

:INVALID_NVIDIA
cls
echo Invalid input
echo.
goto NVIDIADRIVER

:LAPTOP
echo [3/%QN%] Are you using PC (Desktop)?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set PC=FALSE
cls & goto WEBCAM
)
if errorlevel 1 (
>> %configfile% echo set PC=TRUE
cls & goto WEBCAM
)

:WEBCAM
echo [4/%QN%] Will you be using a webcam?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set WEBCAM=FALSE
cls & goto NX
)
if errorlevel 1 (
>> %configfile% echo set WEBCAM=TRUE
cls & goto NX
)

:NX
echo [5/%QN%] Will you be using DEP (Faceit)?
echo.
echo NOTE: Enable only works on Face-It version of ISO
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set NX=FALSE
cls & goto VPN
)
if errorlevel 1 (
>> %configfile% echo set NX=TRUE
cls & goto VPN
)

:VPN
echo [6/%QN%] Will you be using VPN?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set VPN=FALSE
cls & goto BLUETOOTH
)
if errorlevel 1 (
>> %configfile% echo set VPN=TRUE
cls & goto BLUETOOTH
)

:BLUETOOTH
echo [7/%QN%] Will you be using Bluetooth?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set BLUETOOTH=FALSE
cls & goto PRINTING
)
if errorlevel 1 (
>> %configfile% echo set BLUETOOTH=TRUE
cls & goto PRINTING
)

:PRINTING
echo [8/%QN%] Will you be using Printing?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set PRINTING=FALSE
cls & goto NOTIFICATIONS
)
if errorlevel 1 (
>> %configfile% echo set PRINTING=TRUE
cls & goto NOTIFICATIONS
)

:NOTIFICATIONS
echo [9/%QN%] Will you be using Notifications?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set NOTIFICATIONS=FALSE
cls & goto :ANIMATIONS
)
if errorlevel 1 (
>> %configfile% echo set NOTIFICATIONS=TRUE
cls & goto :ANIMATIONS
)

:ANIMATIONS
echo [10/%QN%] Will you be using Animations?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set ANIMATIONS=FALSE
cls & goto CLIPBOARD
)
if errorlevel 1 (
>> %configfile% echo set ANIMATIONS=TRUE
cls & goto CLIPBOARD
)

:CLIPBOARD
echo [11/%QN%] Will you be using Clipboard History?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set CLIPBOARD=FALSE
cls & goto FIREWALL
)
if errorlevel 1 (
>> %configfile% echo set CLIPBOARD=TRUE
cls & goto FIREWALL
)

:FIREWALL
echo [12/%QN%] Will you be using Windows Firewall?
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set FIREWALL=FALSE
cls & goto STORE
)
if errorlevel 1 (
>> %configfile% echo set FIREWALL=TRUE
cls & goto STORE
)

:STORE
set STORE_STATUS=DISABLED
echo [13/%QN%] Would like to install Microsoft Store and keep compatibility for UWP apps?
echo.
echo NOTE: Current state: %STORE_STATUS%
echo NOTE: Disabling it will break About it page in the settings.
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set STORE=FALSE
cls & goto XBOX
)
if errorlevel 1 (
>> %configfile% echo set STORE=TRUE
cls & goto XBOX
)

:XBOX
set XBOX_STATUS=DISABLED
echo [14/%QN%] Would like to install XBOX and GameBar App?
echo.
echo NOTE: Current state: %XBOX_STATUS%
echo.
echo [1] Yes
echo. 
echo [2] No
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
>> %configfile% echo set XBOX=FALSE
cls & goto CONFIRM
)
if errorlevel 1 (
>> %configfile% echo set XBOX=TRUE
cls & goto CONFIRM
)

:CONFIRM
call %configfile%
echo.
echo CONNECTION TYPE : %CONNECTION_TYPE%
echo GPU CONFIG : %GRAPHICS%

if "%GRAPHICS%" EQU "NVIDIA" (
echo NVIDIA DRIVER : %NVIDIADRIVER%
)

if "%GRAPHICS%" EQU "AMD" (
echo AMD DRIVER : %AMDDRIVER%
echo RADEON SOFTWARE : %RADEON_SOFTWARE%
)

echo PC : %PC%
echo WEBCAM : %WEBCAM%
echo NX : %NX%
echo VPN : %VPN%
echo BLUETOOTH : %BLUETOOTH%
echo PRINTING : %PRINTING%
echo NOTIFICATIONS : %NOTIFICATIONS%
echo ANIMATIONS %ANIMATIONS%
echo CLIPBOARD : %CLIPBOARD%
echo FIREWALL : %FIREWALL%
echo STORE : %STORE%
echo XBOX %XBOX%


echo.
echo READ ALL INFO ABOVE CAREFULLY... Is all info above correct?
echo.
echo [1] Yes
echo. 
echo [2] No, i want to select the options again
echo.
choice /c:12 /n >NUL 2>&1
if errorlevel 2 (
del /f /q %configfile% >NUL 2>&1
goto START
)
if errorlevel 1 (
goto INSTALL
)

:INSTALL
call %configfile%
>> %scriptlog% echo CRAWEN POST-INSTALL LOG
>> %scriptlog% echo.
>> %scriptlog% echo -----------------------------------------------------------------------------------------------------------------------------------------------
>> %scriptlog% echo.
>> %scriptlog% echo %date% %time% - Setup initialized
cls

:: POWER PLAN
cls & echo Importing and setting up powerplan...

:: Active powerplan
powercfg -import %windir%\CrawenModules\CrawenOS.pow 11111111-1111-1111-1111-111111111111 >NUL 2>&1
powercfg -setactive 11111111-1111-1111-1111-111111111111 >NUL 2>&1

:: Delete default powerplans
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a >NUL 2>&1
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >NUL 2>&1
powercfg -delete e9a42b02-d5df-448d-aa00-03f14749eb61 >NUL 2>&1

:: FILE SYSTEM
cls & echo Applying File System Modifications...
fsutil behavior set allowextchar 0 >NUL 2>&1
fsutil behavior set disable8dot3 1 >NUL 2>&1
fsutil behavior set disablecompression 1 >NUL 2>&1
fsutil behavior set disabledeletenotify 0 >NUL 2>&1
fsutil behavior set disableencryption 1 >NUL 2>&1
fsutil behavior set disablelastaccess 1 >NUL 2>&1
fsutil behavior set disablespotcorruptionhandling 1 >NUL 2>&1
fsutil behavior set encryptpagingfile 0 >NUL 2>&1
fsutil behavior set quotanotify 86400 >NUL 2>&1
fsutil behavior set symlinkevaluation L2L:1 >NUL 2>&1

:: Device Manager 
cls & echo Disabling Device Manager devices...
%windir%\CrawenModules\devmanview /disable "System Speaker" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "System Timer" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "UMBus Root Bus Enumerator" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "Microsoft System Management BIOS Driver" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "High Precision Event Timer" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "PCI Encryption/Decryption Controller" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "AMD PSP" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "Intel SMBus" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "Intel Management Engine" >NUL 2>&1 
%windir%\CrawenModules\devmanview /disable "PCI Memory Controller" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "PCI standard RAM Controller" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "Composite Bus Enumerator" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "Microsoft Kernel Debug Network Adapter" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "SM Bus Controller" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "Unknown Device" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "NDIS Virtual Network Adapter Enumerator" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "Numeric Data Processor" >NUL 2>&1
%windir%\CrawenModules\devmanview /disable "Microsoft RRAS Root Enumerator" >NUL 2>&1

:: Scheduled Tasks
cls & echo Disabling scheduled tasks...
schtasks /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\AppID\EDP Policy Manager" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\AppID\PolicyConverter" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\ApplicationData\appuriverifierinstall" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Clip\License Validation" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleCommand" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleWnsCommand" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\IntegrityCheck" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\LocateCommandUserSession" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceAccountChange" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceLocationRightsChange" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePeriodic24" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePolicyChange" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceProtectionStateChanged" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceSettingChange" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterUserDevice" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\InstallService\SmartRetry" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\LanguageComponentsInstaller\Installation" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Management\Provisioning\Cellular" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\MUI\LPRemove" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\USB\Usb-Notifications" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Wininet\CacheTask" >NUL 2>&1
schtasks /change /disable /TN "\Microsoft\XblGameSave\XblGameSaveTask" >NUL 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\PLA\System" >NUL 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\PLA" >NUL 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" >NUL 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\RetailDemo" >NUL 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\SyncCenter" >NUL 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\TaskScheduler" >NUL 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\Windows Activation Technologies" >NUL 2>&1

:: Use more privevileges to delete main tasks
%windir%\CrawenModules\NsudoL.exe -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator" >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WindowsUpdate" >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WaaSMedic" >NUL 2>&1

:: Services
cls & echo Configuring services values...
reg add "HKLM\System\CurrentControlSet\Services\3ware" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\ADP80XX" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AmdK8" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AppVClient" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AsyncMac" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\CAD" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\CDPSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\CimFS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\CompositeBus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\CryptSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Dfsc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\DispBrokerDesktopSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\DsmSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\EFS" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Eaphost" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\ErrDev" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\FDResPub" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\IKEEXT" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\InstallService" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\KSecPkg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\KtmRm" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\MSDTC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\SharedAccess" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\ShellHWDetection" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\SiSRaid2" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\SiSRaid4" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\SmsRouter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\SstpSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Telemetry" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\VSTXRAID" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\VerifierExt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WPDBusEnum" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WarpJITSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WindowsTrustedRTProxy" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\arcsas" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\bindflt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\buttonconverter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\cdfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\circlass" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\cnghwassist" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\fdPHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\fdc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\flpydisk" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\fvevol" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\lmhosts" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\mrxsmb20" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\mrxsmb20" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\mrxsmb" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\mrxsmb" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\nvraid" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\rdbss" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\rdyboost" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\rdyboost" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\rdyboost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\sfloppy" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\sppsvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\srv2" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\udfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\umbus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\vsmraid" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\wcnfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1

:: Dependencies 
reg add "HKLM\System\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\rdyboost" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1

:: Filters 
reg add "HKLM\System\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_SZ /d "" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_SZ /d "" /f >NUL 2>&1

:: Configuring
echo Configuring and setting up...

if %CONNECTION_TYPE% EQU ETHERNET (
sc config WlanSvc start=disabled
sc config vwififlt start=demand
for /f "delims=" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\PCI" /s /f "FriendlyName" ^| find "802.11"') do (
    set "device=%%a"
    set device=!device:~30!
    powershell -NoProfile "Get-PnpDevice -FriendlyName '!device!' | Disable-PnpDevice -confirm:$false"
)
) >NUL 2>&1

if %CONNECTION_TYPE% EQU WIFI (
sc config vwififlt start=system
sc config WlanSvc start=auto
) >NUL 2>&1

if %WEBCAM% EQU FALSE (
reg add "HKLM\SYSTEM\CurrentControlSet\Services\swenum" /v "Start" /t REG_DWORD /d "4" /f 
%windir%\CrawenModules\devmanview /disable "Plug and Play Software Device Enumerator"
echo reg add "HKLM\SYSTEM\CurrentControlSet\Services\swenum" /v "Start" /t REG_DWORD /d "4" /f
reg "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
reg "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
reg "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged" /v "Value" /t REG_SZ /d "Deny" /f
) >NUL 2>&1

if %WEBCAM% EQU TRUE (
reg add "HKLM\SYSTEM\CurrentControlSet\Services\swenum" /v "Start" /t REG_DWORD /d "3" /f
%windir%\CrawenModules\devmanview /enable "Plug and Play Software Device Enumerator"
echo reg add "HKLM\SYSTEM\CurrentControlSet\Services\swenum" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged" /v "Value" /t REG_SZ /d "Allow" /f
) >NUL 2>&1

if %NX% equ FALSE bcdedit /set nx AlwaysOff >NUL 2>&1
if %NX% equ TRUE bcdedit /set nx OptIn >NUL 2>&1

if %PC% EQU TRUE (
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Storage" /v "StorageD3InModernStandby" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "ASPMOptOut" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >NUL 2>&1
for %%a in (AllowIdleIrpInD3 D3ColdSupported DeviceSelectiveSuspended EnableIdlePowerManagementEnableSelectiveSuspend
EnhancedPowerManagementEnabled IdleInWorkingState SelectiveSuspendEnabled SelectiveSuspendOn WaitWakeEnabled 
WakeEnabled WdfDirectedPowerTransitionEnable) do (
for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do (
reg add "%%b" /v "%%a" /t REG_DWORD /d "0" /f
) >NUL 2>&1
)
for %%a in (DisableIdlePowerManagement) do (
for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do (
reg add "%%b" /v "%%a" /t REG_DWORD /d "1" /f
) >NUL 2>&1
)
) else (
powercfg /s 381b4222-f694-41f0-9685-ff5bb260df2e >NUL 2>&1
)

if %VPN% EQU FALSE (
%windir%\CrawenModules\devmanview /disable "WAN Miniport (IKEv2)"
%windir%\CrawenModules\devmanview /disable "WAN Miniport (IP)"
%windir%\CrawenModules\devmanview /disable "WAN Miniport (IPv6)"
%windir%\CrawenModules\devmanview /disable "WAN Miniport (L2TP)"
%windir%\CrawenModules\devmanview /disable "WAN Miniport (Network Monitor)"
%windir%\CrawenModules\devmanview /disable "WAN Miniport (PPPOE)"
%windir%\CrawenModules\devmanview /disable "WAN Miniport (PPTP)"
%windir%\CrawenModules\devmanview /disable "WAN Miniport (SSTP)"
%windir%\CrawenModules\devmanview /disable "NDIS Virtual Network Adapter Enumerator"
%windir%\CrawenModules\devmanview /disable "Microsoft RRAS Root Enumerator"
reg add "HKLM\System\CurrentControlSet\Services\IKEEXT" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\SstpSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\Eaphost" /v "Start" /t REG_DWORD /d "4" /f
) >NUL 2>&1

if %VPN% EQU TRUE (
%windir%\CrawenModules\devmanview /enable "WAN Miniport (IKEv2)"
%windir%\CrawenModules\devmanview /enable "WAN Miniport (IP)"
%windir%\CrawenModules\devmanview /enable "WAN Miniport (IPv6)"
%windir%\CrawenModules\devmanview /enable "WAN Miniport (L2TP)"
%windir%\CrawenModules\devmanview /enable "WAN Miniport (Network Monitor)"
%windir%\CrawenModules\devmanview /enable "WAN Miniport (PPPOE)"
%windir%\CrawenModules\devmanview /enable "WAN Miniport (PPTP)"
%windir%\CrawenModules\devmanview /enable "WAN Miniport (SSTP)"
%windir%\CrawenModules\devmanview /enable "NDIS Virtual Network Adapter Enumerator"
%windir%\CrawenModules\devmanview /enable "Microsoft RRAS Root Enumerator"
reg add "HKLM\System\CurrentControlSet\Services\IKEEXT" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\System\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\System\CurrentControlSet\Services\SstpSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\System\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\System\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\System\CurrentControlSet\Services\Eaphost" /v "Start" /t REG_DWORD /d "3" /f
) >NUL 2>&1

if %BLUETOOTH% EQU FALSE (
:: DISABLE BLUETOOTH DEVICES
%windir%\CrawenModules\devcon.exe disable =Bluetooth
%windir%\CrawenModules\devcon.exe disable BTH*

sc config BthA2dp start=disabled 
sc config BthEnum start=disabled 
sc config BthHFEnum start=disabled 
sc config BthLEEnum start=disabled 
sc config BthMini start=disabled 
sc config BthPan start=disabled 
sc config BTHPORT start=disabled 
sc config BTHUSB start=disabled 
sc config HidBth start=disabled 
sc config Microsoft_Bluetooth_AvrcpTransport start=disabled 
sc config RFCOMM start=disabled 

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f 
sc config BluetoothUserService start=disabled 
sc config BTAGService start=disabled 
sc config BthAvctpSvc start=disabled 
sc config bthserv start=disabled 
) >NUL 2>&1

if %BLUETOOTH% EQU TRUE (
:: ENABLE BLUETOOTH DEVICES
%windir%\CrawenModules\devcon.exe enable=Bluetooth
%windir%\CrawenModules\devcon.exe enable BTH*

sc config BthA2dp start=demand 
sc config BthEnum start=demand 
sc config BthHFEnum start=demand 
sc config BthLEEnum start=demand 
sc config BthMini start=demand 
sc config BthPan start=demand 
sc config BTHPORT start=demand 
sc config BTHUSB start=demand 
sc config HidBth start=demand 
sc config Microsoft_Bluetooth_AvrcpTransport start=demand 
sc config RFCOMM start=demand 

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "3" /f 
sc config BluetoothUserService start=demand 
sc config BTAGService start=demand 
sc config BthAvctpSvc start=demand 
sc config bthserv start=demand 

) >NUL 2>&1

if %PRINTING% EQU FALSE (
:: DISABLE PRINTING DEVICES
%windir%\CrawenModules\devcon.exe disable "=Printer"
%windir%\CrawenModules\devcon.exe disable "=PrintQueue"

sc config Spooler start=disabled
sc config PrintNotify start=disabled
sc config PrintWorkflowUserSvc start=disabled
) >NUL 2>&1

if %PRINTING% EQU TRUE (
%windir%\CrawenModules\devcon.exe enable "=Printer"
%windir%\CrawenModules\devcon.exe enable "=PrintQueue"

sc config Spooler start=demand
sc config PrintNotify start=demand
sc config PrintWorkflowUserSvc start=demand
) >NUL 2>&1

if %NOTIFICATIONS% EQU FALSE (
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
) >NUL 2>&1

if %NOTIFICATIONS% EQU TRUE (
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "1" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /f
reg delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /f
) >NUL 2>&1

if %ANIMATIONS% EQU FALSE (
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
) >NUL 2>&1

if %ANIMATIONS% EQU TRUE (
reg delete "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /f
reg delete "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9e3e078012000000" /f
) >NUL 2>&1

if %CLIPBOARD% EQU FALSE (
for /f %%I in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /s /k /f cbdhsvc ^| find /i "cbdhsvc" ') do (
  reg add "%%I" /v "Start" /t REG_DWORD /d "4" /f
)
sc config DsSvc start=disabled
reg add "HKEY_CURRENT_USER\Software\Microsoft\Clipboard" /v "EnableClipboardHistory" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f
) >NUL 2>&1

if %CLIPBOARD% EQU TRUE (
for /f %%I in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /s /k /f cbdhsvc ^| find /i "cbdhsvc" ') do (
  reg add "%%I" /v "Start" /t REG_DWORD /d "3" /f
)
sc config DsSvc start=auto
reg add "HKEY_CURRENT_USER\Software\Microsoft\Clipboard" /v "EnableClipboardHistory" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /f
) >NUL 2>&1

if %FIREWALL% EQU FALSE (
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f
) >NUL 2>&1

if %FIREWALL% EQU TRUE (
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
) >NUL 2>&1

if %STORE% EQU TRUE (
cls & echo Installing Microsoft Store...
curl -L -o %TEMP%\Microsoft.WindowsStore.msixbundle https://github.com/CrawenOS/Apps/raw/main/Microsoft.WindowsStore.msixbundle --progress-bar
start %TEMP%\Microsoft.WindowsStore.msixbundle
)

if %STORE% EQU FALSE (
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f

sc config InstallService start=disabled
sc config mpssvc start=disabled
sc config wlidsvc start=disabled
sc config AppXSvc start=disabled
sc config BFE start=disabled
sc config TokenBroker start=disabled
sc config LicenseManager start=disabled
sc config AppXSVC start=disabled
sc config ClipSVC start=disabled
sc config FileInfo start=disabled
sc config FileCrypt start=disabled
)

if %XBOX% EQU TRUE (
cls & echo Installing Xbox Apps...
curl -L -o %TEMP%\Microsoft.XboxGameBar.appxbundle https://github.com/CrawenOS/Apps/raw/main/Microsoft.XboxGameBar.appxbundle --progress-bar
start %TEMP%\Microsoft.XboxGameBar.appxbundle

curl -L -o %TEMP%\XboxInstaller.exe https://github.com/CrawenOS/Apps/raw/main/XboxInstaller.exe --progress-bar
start %TEMP%\XboxInstaller.exe
)

if %XBOX% EQU FALSE (
cls & echo Disabling XBOX compatibility
sc config XblAuthManager start=disabled
sc config XblGameSave start=disabled
sc config XboxGipSvc start=disabled
sc config XboxNetApiSvc start=disabled
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
)

cls & echo Configuration has ended...

:: INSTALL THE GPU DRIVER
if %GRAPHICS% EQU AMD goto AMD
if %GRAPHICS% EQU NVIDIA goto NVIDIA
if %GRAPHICS% EQU INTEL goto DIRECTX

:AMD 
cls & echo Downloading %AMDDRIVER% version of driver
echo.
if %AMDDRIVER% EQU 22.5.1 (
curl -L -H "Referer: https://www.amd.com/en/support/kb/release-notes/rn-rad-win-22-5-1" https://drivers.amd.com/drivers/WHQL-AMD-Software-Adrenalin-Edition-22.5.1-Win10-Win11-May10.exe -o "%temp%\%AMDDRIVER%.zip" --progress-bar
)
if %AMDDRIVER% EQU 22.5.PR (
curl -L -H "Referer: https://www.amd.com/en/support/kb/release-notes/rn-rad-win-preview-may2022" https://drivers.amd.com/drivers/AMD-Software-Preview-Driver-May-2022.exe -o "%temp%\%AMDDRIVER%.zip" --progress-bar
)
if %AMDDRIVER% EQU 21.10.2 (
curl -L -H "Referer: https://www.amd.com/en/support/kb/release-notes/rn-rad-win-21-10-2" https://drivers.amd.com/drivers/radeon-software-adrenalin-2020-21.10.2-win10-win11-64bit-oct25.exe -o "%temp%\%AMDDRIVER%.zip" --progress-bar
)

cls & echo Extracting driver...
%windir%\CrawenModules\7z.exe x -y -o"%temp%\%AMDDRIVER%" "%temp%\%AMDDRIVER%.zip" >NUL 2>&1

cls & echo Debloating driver...
rd /s /q "%temp%\%AMDDRIVER%\Packages\Drivers\Display\WT6A_INF\amdlog" >NUL 2>&1
rd /s /q "%temp%\%AMDDRIVER%\Packages\Drivers\Display\WT6A_INF\amdfendr" >NUL 2>&1
rd /s /q "%temp%\%AMDDRIVER%\Packages\Drivers\Display\WT6A_INF\amdxe" >NUL 2>&1
rd /s /q "%temp%\%AMDDRIVER%\Packages\Drivers\Display\WT6A_INF\amdafd" >NUL 2>&1

:: INSTALL DRIVER
cls & echo Installing %AMDDRIVER%... This may take a few minutes be patient.
echo.
pnputil /add-driver "%temp%\%AMDDRIVER%\Packages\Drivers\Display\WT6A_INF\*.inf" /install


if %RADEON_SOFTWARE% EQU TRUE (
for /f %%a in ('dir /b "!temp!\!AMDDRIVER!\Packages\Drivers\Display\WT6A_INF\B3*"') do (
if exist "!temp!\!AMDDRIVER!\Packages\Drivers\Display\WT6A_INF\%%a\ccc2_install.exe" (
%windir%\CrawenModules\7z.exe x -y -o"!temp!\!AMDDRIVER!_PANEL" "!temp!\!AMDDRIVER!\Packages\Drivers\Display\WT6A_INF\%%a\ccc2_install.exe"
"!temp!\!AMDDRIVER!_PANEL\CN\cnext\cnext64\ccc-next64.msi" /quiet /norestart
      )
  )
) >NUL 2>&1

cls & echo Applying AMD GPU tweaks...
for /f %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /s /v "DriverDesc"^| findstr "HKEY AMD ATI"') do if /i "%%i" neq "DriverDesc" (set "REGPATH_AMD=%%i")

:: Disable AMD services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AMD Log Utility" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AMD Crash Defender Service" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AMD External Events Utility" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

::AMD Tweaks
for %%i in (AsicOnLowPower EnableUlps PP_GPUPowerDownEnabled PP_ThermalAutoThrottlingEnable KMD_EnableContextBasedPowerManagement
KMD_ChillEnabled EnableUvdClockGating EnableVceSwClockGating StutterMode DisableBlockWrite) do reg add "!REGPATH_AMD!" /v "%%i" /t REG_DWORD /d "0" /f >NUL 2>&1

for %%i in (AGCOOPTION_DisableGPIOPowerSaveMode PP_SclkDeepSleepDisable PP_DisableSQRamping PP_DisablePowerContainment DisableDrmdmaPowerGating 
DisableUVDPowerGating DisableUVDPowerGatingDynamic DisableVCEPowerGating DisableSAMUPowerGating DisablePowerGating DisableAllClockGating 
PP_ForceHighDPMLevel PP_Force3DPerformanceMode DisableDMACopy) do reg add "!REGPATH_AMD!" /v "%%i" /t REG_DWORD /d "1" /f >NUL 2>&1

reg add "!REGPATH_AMD!\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f >NUL 2>&1
reg add "!REGPATH_AMD!\UMD" /v "FlipQueueSize" /t REG_BINARY /d "3100" /f >NUL 2>&1
reg add "!REGPATH_AMD!\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f >NUL 2>&1
reg add "!REGPATH_AMD!\UMD" /v "Tessellation_OPTION" /t REG_BINARY /d "3200" /f >NUL 2>&1
reg add "!REGPATH_AMD!\UMD" /v "Tessellation" /t REG_BINARY /d "3100" /f >NUL 2>&1
reg add "!REGPATH_AMD!\UMD" /v "VSyncControl" /t REG_BINARY /d "3000" /f >NUL 2>&1
reg add "!REGPATH_AMD!\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f >NUL 2>&1

goto DIRECTX

:NVIDIADRIVER
cls & echo Downloading %NVIDIADRIVER%
echo.
441.41 442.74 456.71 457.30 457.51 461.92 466.11 472.12 512.77
if "%NVIDIADRIVER%" EQU "441.41" (
curl -L "https://us.download.nvidia.com/Windows/441.41/441.41-desktop-win10-64bit-international-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)
if "%NVIDIADRIVER%" EQU "442.74" (
curl -L "https://us.download.nvidia.com/Windows/442.74/442.74-desktop-win10-64bit-international-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)
if "%NVIDIADRIVER%" EQU "456.71" (
curl -L "https://us.download.nvidia.com/Windows/456.71/456.71-desktop-win10-64bit-international-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)
if "%NVIDIADRIVER%" EQU "457.30" (
curl -L "https://us.download.nvidia.com/Windows/457.30/457.30-desktop-win10-64bit-international-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)
if "%NVIDIADRIVER%" EQU "457.51" (
curl -L "https://us.download.nvidia.com/Windows/457.51/457.51-desktop-win10-64bit-international-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)
if "%NVIDIADRIVER%" EQU "461.92" (
curl -L "https://us.download.nvidia.com/Windows/461.92/461.92-desktop-win10-64bit-international-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)
if "%NVIDIADRIVER%" EQU "466.11" (
curl -L "https://us.download.nvidia.com/Windows/466.11/466.11-desktop-win10-64bit-international-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)
if "%NVIDIADRIVER%" EQU "472.12" (
curl -L "https://us.download.nvidia.com/Windows/472.12/472.12-desktop-win10-win11-64bit-international-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)
if "%NVIDIADRIVER%" EQU "512.77" (
curl -L "https://us.download.nvidia.com/Windows/512.77/512.77-desktop-win10-win11-64bit-international-dch-whql.zip" -o "%temp%\%NVIDIADRIVER%.zip" --progress-bar
)

cls & echo Extracting driver...
%windir%\CrawenModules\7z.zip x -y -o"%temp%\%NVIDIADRIVER%" "%temp%\%NVIDIADRIVER%.zip" >NUL 2>&1

cls & echo Debloating driver...
for /f %%a in ('dir "%temp%\%NVIDIADRIVER%" /b') do (
if "%%a" NEQ "Display.Driver" if "%%a" NEQ "NVI2" if "%%a" NEQ "EULA.txt" if "%%a" NEQ "ListDevices.txt" if "%%a" NEQ "setup.cfg" if "%%a" NEQ "setup.exe" (
rd /s /q "%temp%\%NVIDIADRIVER%\%%a" >NUL 2>&1
del /f /q "%temp%\%NVIDIADRIVER%\%%a" >NUL 2>&1
)
)

"%windir%\CrawenModules\strip_setupcfg.exe" "%temp%\%NVIDIADRIVER%\setup.cfg" "%temp%\%NVIDIADRIVER%\m_setup.cfg"
del /f /q "%temp%\%NVIDIADRIVER%\setup.cfg" >NUL 2>&1
REN "%temp%\%NVIDIADRIVER%\m_setup.cfg" "setup.cfg" >NUL 2>&1
cls & echo Installing %NVIDIADRIVER%...
"%temp%\%NVIDIADRIVER%\setup.exe" /s
cls

:: APPLY NVIDIA CONTROL PANEL SETTINGS
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do (
for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\%%i" /v "Driver"') do (
for /f %%i in ('echo %%a ^| findstr "{"') do (
%= VIDEO =%
%= ADJUST VIDEO IMAGE SETTINGS =%
%= EDGE ENHANCEMENT - USE THE NVIDIA SETTING =%
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_Edge_Enhance" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
%= EDGE ENHANCEMENT 0 =%
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_VAL_Edge_Enhance" /t REG_DWORD /d "0" /f >NUL 2>&1
%= NOISE REDUCTION - USE THE NVIDIA SETTING =%
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_Noise_Reduce" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
%= NOISE REDUCTION - 0 =%
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_VAL_Noise_Reduce" /t REG_DWORD /d "0" /f >NUL 2>&1
%= DEINTERLACING - DISABLE "USE INVERSE TELECINE" =%
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XALG_Cadence" /t REG_BINARY /d "0000000000000000" /f >NUL 2>&1

%= ADJUST VIDEO COLOR SETTINGS =%
%= COLOR ADJUSTMENTS - WITH THE NVIDIA SETTINGS =%
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_Contrast" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_RGB_Gamma_G" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_RGB_Gamma_R" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_RGB_Gamma_B" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_Hue" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_Saturation" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_Brightness" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XEN_Color_Range" /t REG_DWORD /d "2147483649" /f >NUL 2>&1
%= DYNAMIC RANGE - FULL =%
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "_User_SUB0_DFP2_XALG_Color_Range" /t REG_BINARY /d "0000000000000000" /f >NUL 2>&1

%= DISABLE HDCP =%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMHdcpKeyglobZero" /t REG_DWORD /d 1 /f >NUL 2>&1

%= DEVELOPER - MANAGE GPU PERFORMANCE COUNTERS - "ALLOW ACCESS TO THE GPU PERFORMANCE COUNTERS TO ALL USERS" =%
reg add "HKLM\System\CurrentControlSet\Control\Class\%%i" /v "RmProfilingAdminOnly" /t REG_DWORD /d "0" /f >NUL 2>&1

%= CREDIT TO TIMECARD =%
if %DISABLE_NVIDIA_PSTATES% EQU TRUE reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >NUL 2>&1
)
)
)
:: DESKTOP > ENABLE DEVELOPER SETTINGS 
reg add "HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "NvDevToolsVisible" /t REG_DWORD /d "1" /f >NUL 2>&1

:: ADJUST IMAGE SETTINGS WITH PREVIEW - "USE THE ADVANCED 3D IMAGE SETTINGS"
reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v "Gestalt" /t REG_DWORD /d "513" /f >NUL 2>&1

:: CONFIGURE SURROUND, PHYSX - PROCESSOR: GPU
reg add "HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "NvCplPhysxAuto" /t REG_DWORD /d "0" /f >NUL 2>&1

:: MANAGE 3D SETTINGS - UNHIDE SILK SMOOTHNESS OPTION
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f >NUL 2>&1

:: DEVELOPER - MANAGE GPU PERFORMANCE COUNTERS - "ALLOW ACCESS TO THE GPU PERFORMANCE COUNTERS TO ALL USERS"
reg add "HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmProfilingAdminOnly" /t REG_DWORD /d "0" /f >NUL 2>&1

:: ONLY DISABLE WRITE COMBINING IN SUPPORTED DRIVERS
for %%a in (441.41) do (
if %NVIDIADRIVER% EQU %%a reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
)

for /f "delims=" %%a in ('reg query HKLM\System\CurrentControlSet\Services\nvlddmkm\State\DisplayDatabase') do (
%= OVERRIDE THE SCALING MODE SET BY GAMES AND PROGRAMS =%
reg add "%%a" /v "ScalingConfig" /t REG_BINARY /d "DB01000010000000800000006C010000" /f >NUL 2>&1

%= DISPLAY - CHANGE RESOLUTION - "USE NVIDIA COLOR SETTINGS" =%
reg add "%%a" /v "ColorformatConfig" /t REG_BINARY /d "DB02000014000000000A00080000000003010000" /f >NUL 2>&1
)
goto DIRECTX

:DIRECTX
cls & echo Downloading DirectX
echo.
curl -L "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe" -o "%TEMP%\DirectX.exe" --progress-bar
%windir%\CrawenModules\7z.exe x -y -o"%TEMP%\DirectX" "%TEMP%\DirectX.exe" >NUL 2>&1

cls & echo Installing DirectX...
"%TEMP%\DirectX\dxsetup.exe" /silent

cls & echo Downloading 7-Zip
curl -L https://www.7-zip.org/a/7z2107-x64.exe -o %TEMP%\7z.exe --progress-bar

cls & echo Installing 7-Zip and importing settings...
call %TEMP%\7z.exe /S

reg add "HKCU\Software\7-Zip\Options" /v "ContextMenu" /t reg_DWORD /d "2147488038" /f >NUL 2>&1
reg add "HKCU\Software\7-Zip\Options" /v "ElimDupExtract" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.001" /ve /t reg_SZ /d "7-Zip.001" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.7z" /ve /t reg_SZ /d "7-Zip.7z" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.arj" /ve /t reg_SZ /d "7-Zip.arj" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.bz2" /ve /t reg_SZ /d "7-Zip.bz2" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.bzip2" /ve /t reg_SZ /d "7-Zip.bzip2" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.cab" /ve /t reg_SZ /d "7-Zip.cab" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.cpio" /ve /t reg_SZ /d "7-Zip.cpio" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.deb" /ve /t reg_SZ /d "7-Zip.deb" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.dmg" /ve /t reg_SZ /d "7-Zip.dmg" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.fat" /ve /t reg_SZ /d "7-Zip.fat" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.gz" /ve /t reg_SZ /d "7-Zip.gz" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.gzip" /ve /t reg_SZ /d "7-Zip.gzip" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.hfs" /ve /t reg_SZ /d "7-Zip.hfs" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.iso" /ve /t reg_SZ /d "7-Zip.iso" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.lha" /ve /t reg_SZ /d "7-Zip.lha" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.lzh" /ve /t reg_SZ /d "7-Zip.lzh" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.lzma" /ve /t reg_SZ /d "7-Zip.lzma" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.ntfs" /ve /t reg_SZ /d "7-Zip.ntfs" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.rar" /ve /t reg_SZ /d "7-Zip.rar" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.rpm" /ve /t reg_SZ /d "7-Zip.rpm" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.squashfs" /ve /t reg_SZ /d "7-Zip.squashfs" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.swm" /ve /t reg_SZ /d "7-Zip.swm" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.tar" /ve /t reg_SZ /d "7-Zip.tar" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.taz" /ve /t reg_SZ /d "7-Zip.taz" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.tbz" /ve /t reg_SZ /d "7-Zip.tbz" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.tbz2" /ve /t reg_SZ /d "7-Zip.tbz2" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.tgz" /ve /t reg_SZ /d "7-Zip.tgz" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.tpz" /ve /t reg_SZ /d "7-Zip.tpz" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.txz" /ve /t reg_SZ /d "7-Zip.txz" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.vhd" /ve /t reg_SZ /d "7-Zip.vhd" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.wim" /ve /t reg_SZ /d "7-Zip.wim" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.xar" /ve /t reg_SZ /d "7-Zip.xar" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.xz" /ve /t reg_SZ /d "7-Zip.xz" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.z" /ve /t reg_SZ /d "7-Zip.z" /f >NUL 2>&1
reg add "HKLM\Software\Classes\.zip" /ve /t reg_SZ /d "7-Zip.zip" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.001" /ve /t reg_SZ /d "001 Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.001\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,9" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.001\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.001\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.001\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.7z" /ve /t reg_SZ /d "7z Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.7z\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,0" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.7z\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.7z\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.7z\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.arj" /ve /t reg_SZ /d "arj Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.arj\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,4" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.arj\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.arj\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.arj\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bz2" /ve /t reg_SZ /d "bz2 Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bz2\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bz2\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bz2\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bz2\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bzip2" /ve /t reg_SZ /d "bzip2 Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bzip2\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bzip2\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bzip2\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.bzip2\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cab" /ve /t reg_SZ /d "cab Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cab\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,7" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cab\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cab\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cab\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cpio" /ve /t reg_SZ /d "cpio Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cpio\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,12" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cpio\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cpio\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.cpio\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.deb" /ve /t reg_SZ /d "deb Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.deb\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,11" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.deb\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.deb\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.deb\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.dmg" /ve /t reg_SZ /d "dmg Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.dmg\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,17" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.dmg\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.dmg\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.dmg\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.fat" /ve /t reg_SZ /d "fat Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.fat\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,21" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.fat\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.fat\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.fat\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gz" /ve /t reg_SZ /d "gz Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gz\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gz\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gz\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gz\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gzip" /ve /t reg_SZ /d "gzip Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gzip\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gzip\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gzip\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.gzip\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.hfs" /ve /t reg_SZ /d "hfs Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.hfs\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,18" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.hfs\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.hfs\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.hfs\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.iso" /ve /t reg_SZ /d "iso Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.iso\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,8" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.iso\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.iso\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.iso\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lha" /ve /t reg_SZ /d "lha Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lha\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,6" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lha\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lha\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lha\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzh" /ve /t reg_SZ /d "lzh Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzh\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,6" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzh\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzh\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzh\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzma" /ve /t reg_SZ /d "lzma Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzma\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,16" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzma\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzma\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.lzma\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.ntfs" /ve /t reg_SZ /d "ntfs Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.ntfs\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,22" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.ntfs\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.ntfs\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.ntfs\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rar" /ve /t reg_SZ /d "rar Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rar\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,3" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rar\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rar\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rar\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rpm" /ve /t reg_SZ /d "rpm Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rpm\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,10" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rpm\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rpm\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.rpm\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.squashfs" /ve /t reg_SZ /d "squashfs Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.squashfs\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,24" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.squashfs\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.squashfs\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.squashfs\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.swm" /ve /t reg_SZ /d "swm Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.swm\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,15" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.swm\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.swm\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.swm\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tar" /ve /t reg_SZ /d "tar Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tar\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,13" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tar\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tar\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tar\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.taz" /ve /t reg_SZ /d "taz Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.taz\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,5" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.taz\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.taz\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.taz\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz" /ve /t reg_SZ /d "tbz Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz2" /ve /t reg_SZ /d "tbz2 Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz2\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz2\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz2\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz2\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tbz\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tgz" /ve /t reg_SZ /d "tgz Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tgz\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tgz\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tgz\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tgz\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tpz" /ve /t reg_SZ /d "tpz Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tpz\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tpz\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tpz\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.tpz\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.txz" /ve /t reg_SZ /d "txz Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.txz\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,23" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.txz\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.txz\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.txz\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.vhd" /ve /t reg_SZ /d "vhd Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.vhd\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,20" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.vhd\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.vhd\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.vhd\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.wim" /ve /t reg_SZ /d "wim Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.wim\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,15" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.wim\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.wim\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.wim\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xar" /ve /t reg_SZ /d "xar Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xar\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,19" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xar\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xar\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xar\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xz" /ve /t reg_SZ /d "xz Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xz\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,23" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xz\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xz\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.xz\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.z" /ve /t reg_SZ /d "z Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.z\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,5" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.z\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.z\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.z\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.zip" /ve /t reg_SZ /d "zip Archive" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.zip\DefaultIcon" /ve /t reg_SZ /d "C:\Program Files\7-Zip\7z.dll,1" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.zip\shell" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.zip\shell\open" /ve /t reg_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Classes\7-Zip.zip\shell\open\command" /ve /t reg_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f >NUL 2>&1

cls & echo Installing Visual Redist C++
curl -L https://github.com/abbodi1406/vcredist/releases/download/v%VS_VER%/VisualCppRedist_AIO_x86_x64_60.zip -o %TEMP%\vcredist.zip --progress-bar
%windir%\CrawenModules\7z.exe e %TEMP%\vcredist.zip -o%TEMP%\
call %TEMP%\VisualCppRedist_AIO_x86_x64.exe /ai

:GLOBAL_TWEAKS
>> %scriptlog% echo %date% %time% - Started adding global tweaks


:: MEMORY TWEAKS
cls & echo Optimizing memory...

:: NTFS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableCompression" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t Reg_DWORD /d "1" /f >NUL 2>&1

:: Prefetch & Superfetch
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable boot files defragmentation at startup
reg add "HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "N" /f >NUL 2>&1

:: Disable updating Group Policy at startup
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "SynchronousMachineGroupPolicy" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "SynchronousUserGroupPolicy" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Memory Compression
powershell -Command "Disable-MMAgent -mc" >NUL 2>&1

:: Memory Management
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
 
:: Speedup Startup
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f >NUL 2>&1


:: MITIGATIONS
cls & echo Disabling mitigations...

:: Disable DmaRemapping
for /f %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f DmaRemappingCompatible ^| find /i "Services\" ') do (
reg add "%%i" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >NUL 2>&1
)

:: CSRSS mitigations
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t REG_DWORD /d "3" /f >NUL 2>&1

:: Set System Processes Priority below normal
for %%i in (lsass.exe sppsvc.exe SearchIndexer.exe fontdrvhost.exe sihost.exe ctfmon.exe) do (
  reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%i\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "5" /f
)
:: Set background apps priority below normal
for %%i in (OriginWebHelperService.exe ShareX.exe EpicWebHelper.exe SocialClubHelper.exe steamwebhelper.exe) do (
  reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%i\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "5" /f
)

:: Disable FTH
reg add "HKLM\Software\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Chain Validation
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Correct Mitigation Values
powershell -NoProfile -Command Set-ProcessMitigation -System -Disable CFG >NUL 2>&1
for /f "tokens=3 skip=2" %%i in ('reg query "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do set mitigation_mask=%%i
for /l %%i in (0,1,9) do set mitigation_mask=!mitigation_mask:%%i=2!
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f >NUL 2>&1

:: DISABLE INTEL DRIVERS ON AMD SYSTEMS AND VICE VERSA

for /F "tokens=* skip=1" %%n in ('wmic cpu get Manufacturer ^| findstr "."') do set CPUManufacturer=%%n
if %CPUManufacturer% EQU AuthenticAMD (
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iagpio" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iai2c" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iaLPSS2i_GPIO2" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iaLPSS2i_GPIO2_BXT_P" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iaLPSS2i_I2C" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iaLPSS2i_I2C_BXT_P" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iaLPSSi_GPIO" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iaLPSSi_I2C" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iaStorAVC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\iaStorV" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\intelide" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\intelpep" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\intelppm" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
)

if %CPUManufacturer% EQU GenuineIntel (
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\AmdK8" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\AmdPPM" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\amdsata" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\amdsbs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
%windir%\CrawenModules\NsudoL.exe -U:C -P:E -Wait reg add "HKLM\System\CurrentControlSet\Services\amdxata" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
)

:: WINDOWS TWEAKS

:: Delete Defaultuser0 used during OOBE
net user defaultuser0 /delete >NUL 2>&1 

:: Disable "Administrator" used using OEM
net user administrator /active:no >NUL 2>&1 

:: Security Tweaks 
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v "SusClientId" /t REG_SZ /d "00000000-0000-0000-0000-000000000000" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "NodeType" /t REG_DWORD /d "2" /f >NUL 2>&1

:: Restrict Windows communication
reg add "HKLM\Software\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Win32PrioritySeparation 26 hex/38 dec
reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >NUL 2>&1

:: Hibernate
powercfg /h off >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: MMCSS
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d "10000" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "NoLazyMode" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "NoLazyMode" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Hung Apps & Delay
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9A12038010000000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v AutoColorization /t REG_DWORD /d "1" /f >NUL 2>&1

:: Enable Hardware Accelerated Scheduling (HAGS)
reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f >NUL 2>&1

:: Force contiguous memory allocation in the DirectX Graphics kernel
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Keyboard Optimizations
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Data Queue Sizes
reg add "HKLM\System\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "50" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "50" /f >NUL 2>&1

:: Explorer
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoRemoteDestinations" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Application Compatability
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f >NUL 2>&1

:: WMP Optimizations
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer" /v "GroupPrivacyAcceptance" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "AcceptedEULA" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "FirstTime" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Restore and configure Photo Viewer
for %%i in (tif tiff bmp dib gif jfif jpe jpeg jpg jxr png) do (
reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".%%~i" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
) >NUL 2>&1

:: Disable blocking downloads
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable PerfTask
reg add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Show the desktop wallpaper at its highest quality
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /t REG_DWORD /v "JPEGImportQuality" /d "100" /f >NUL 2>&1

:: Disable Transparency
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Maintenance
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Do not reduce sounds while calling
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f >NUL 2>&1

:: Change OEM information
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /t REG_SZ /v "Manufacturer" /d "CrawenOS" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /t REG_SZ /v "Model" /d "v0.2" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /t REG_SZ /v "SupportURL" /d "https://discord.gg/crawenos" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /t REG_SZ /v "SupportHours" /d "At any moment." /f >NUL 2>&1

:: Telemetry
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Data Collection
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Remote assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowFullControl" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Sleep Study
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: KMS Data sending
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f >NUL 2>&1


::::::::::::::
:: Internet ::
::::::::::::::

:: Disable Nagle's Algorithm
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do (
  reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
  reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
  reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
)

:: QOS
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Netsh
netsh int tcp set heuristics disabled >NUL 2>&1
netsh int tcp set supplemental Internet congestionprovider=ctcp >NUL 2>&1
netsh int tcp set global timestamps=disabled >NUL 2>&1
netsh int tcp set global rsc=disabled >NUL 2>&1
for /f "tokens=1" %%i in ('netsh int ip show interfaces ^| findstr [0-9]') do (
netsh int ip set interface %%i routerdiscovery=disabled store=persistent
) >NUL 2>&1
powershell -NoProfile -Command "Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6, ms_msclient, ms_pacer, ms_server" >NUL 2>&1

for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Class" /v "*WakeOnMagicPacket" /s ^| findstr  "HKEY"') do (
    for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (
        reg add "%%i" /v "GigaLite" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*EEE" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*FlowControl" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (
        reg add "%%i" /v "PowerSavingMode" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnableSavePowerNow" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnablePowerManagement" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnableDynamicPowerGating" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnableConnectedPowerGating" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "AutoDisableGigabit" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AutoDisableGigabit" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "AdvancedEEE" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AdvancedEEE" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ULPMode" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnablePME" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnablePME" /t REG_SZ /d "0" /f
    )
) >NUL 2>&1


:::::::::::::::::
:: Main Tweaks ::
:::::::::::::::::

:: ENABLE MSI MODE FOR GPU
for /f %%a in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
) >NUL 2>&1

:: ENABLE MSI MODE FOR USB
for /f %%a in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
) >NUL 2>&1

:: ENABLE MSI MODE FOR NETWORK ADAPTER
for /f %%a in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
) >NUL 2>&1

:: RAM 
for /f "tokens=2 delims==" %%a in ('wmic os get TotalVisibleMemorySize /format:value ^| findstr "TotalVisibleMemorySize"') do set "TotalVisibleMemorySize=%%a"
set /a ram=%TotalVisibleMemorySize%+1024000

reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%ram%" /f >NUL 2>&1
if %ram% LSS 8000000 (
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "33554432" /f >NUL 2>&1
) else if %ram% LSS 16000000 (
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "2" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "67108864" /f >NUL 2>&1
) else (
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "2" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "2" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "134217728" /f >NUL 2>&1
)

:: BCDedit
bcdedit /deletevalue useplatformclock >NUL 2>&1
bcdedit /set disabledynamictick yes >NUL 2>&1
bcdedit /set useplatformtick yes >NUL 2>&1
bcdedit /set bootmenupolicy Legacy >NUL 2>&1
bcdedit /set bootux disabled >NUL 2>&1
bcdedit /set quietboot yes >NUL 2>&1
bcdedit /set {globalsettings} custom:16000067 true >NUL 2>&1
bcdedit /set {globalsettings} custom:16000068 true >NUL 2>&1
bcdedit /set {globalsettings} custom:16000069 true >NUL 2>&1
bcdedit /set tpmbootentropy ForceDisable >NUL 2>&1
bcdedit /set hypervisorlaunchtype off >NUL 2>&1
bcdedit /set {current} description "Crawen" >NUL 2>&1


:::::::::::::::
:: FINISHING ::
:::::::::::::::

:: Misc Tweaks
lodctr /r >NUL 2>&1
lodctr /r >NUL 2>&1

shutdown /r /f /t 10 /c "SETUP COMPLETED: RESTARTING..."

:: Delete files used in the Configuration
del /s /f /q %WINDIR%\CrawenModules >NUL 2>&1
del /s /f /q %TEMP% >NUL 2>&1
DEL "%~f0" >NUL 2>&1
exit