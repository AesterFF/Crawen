:: CrawenOS PostInstall Script
:: Version 0.2

:: CREDITS:
:: 420bud420
:: Amit
:: Artanis
:: CatGamerOP
:: EchoX
:: imribiy
:: Melody
:: Phlegm
:: Zusier

@echo off
>NUL 2>&1 "%WinDir%\System32\cacls.exe" "%WinDir%\System32\config\system"

SETLOCAL EnableDelayedExpansion

:: Prepare to script
for /f "tokens=2 delims==" %%a in ('wmic os get TotalVisibleMemorySize /format:value ^| findstr "TotalVisibleMemorySize"') do set "TotalVisibleMemorySize=%%a"
set /a RAM=%TotalVisibleMemorySize%+1024000

for /f "delims=:{}" %%i in ('wmic path Win32_systemenclosure get ChassisTypes^| findstr [0-9]') do set "CHASSIS=%%i"
set /a LAPTOP=0
if %CHASSIS% GTR 7 ( 
if %CHASSIS% LSS 17 ( set /a LAPTOP=1 )
if %CHASSIS% GTR 28 ( set /a LAPTOP=1 ) 
)

break>C:\Users\Public\success.txt
echo STARTED > C:\Users\Public\success.txt

:: Install and optimize 7-Zip
call %WINDIR%\Crawen\7zip.msi /quiet /norestart && del /f /q "%WINDIR%\Crawen\7zip.msi" >NUL 2>&1
NSudoL -ShowWindowMode:hide -Wait -U:T -P:E reg import "%WINDIR%\Crawen\7-Zip.reg" >NUL 2>&1 && del /f /q "%WINDIR%\Crawen\7-Zip.reg" >NUL 2>&1

:::::::::::::::::::::::::
::Storage Optimizations::
:::::::::::::::::::::::::

:: Storage System - AMIT
fsutil behavior set allowextchar 0 > NUL 2>&1
fsutil behavior set Bugcheckoncorrupt 0 > NUL 2>&1
fsutil behavior set disable8dot3 1 > NUL 2>&1
fsutil behavior set disablecompression 1 > NUL 2>&1
fsutil behavior set disabledeletenotify 0 >NUL 2>&1
fsutil behavior set disableencryption 1 > NUL 2>&1
fsutil behavior set disablelastaccess 1 > NUL 2>&1
fsutil behavior set disablespotcorruptionhandling 1 > NUL 2>&1
fsutil behavior set encryptpagingfile 0 > NUL 2>&1
fsutil behavior set quotanotify 86400 > NUL 2>&1
fsutil behavior set symlinkevaluation L2L:1 > NUL 2>&1

:: Prefetch & Superfetch
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >NUL 2>&1


:::::::::::::::::::::::::
::Memory Optimizations:::
:::::::::::::::::::::::::

:: Memory Compression
powershell -Command "Disable-MMAgent -mc"

:: Memory Management
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Paging
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f >NUL 2>&1

:: SvcSplitThreshold
reg add "HKLM\System\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%ram%" /f >NUL 2>&1

:: Large System Cache
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >NUL 2>&1
 
:: Speedup Startup
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f >NUL 2>&1


:::::::::::::::
::Mitigations::
:::::::::::::::

:: Disable DmaRemapping
for /f %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f DmaRemappingCompatible ^| find /i "Services\" ') do (
	reg add "%%i" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >NUL 2>&1
)

::CSRSS mitigations
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
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f >nul 2>&1

:: Spectre & Meltdown
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d "3" /f >NUL 2>&1

:::::::::::::::
::Mitigations::
:::::::::::::::

:: DWM
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Security Tweaks 
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "NodeType" /t REG_DWORD /d "2" /f >NUL 2>&1

:: Restrict Windows communication
reg add "HKLM\Software\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d "1" /f

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

:: Hung Apps, Delay
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9A12038010000000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f >NUL 2>&1

:: Enable Hardware Accelerated Scheduling (HAGS)
reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f >NUL 2>&1

:: Mouse Optimizations
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f >NUL 2>&1
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >NUL 2>&1
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d 0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000 /f >NUL 2>&1
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d 0000000000000000000038000000000000007000000000000000A800000000000000E00000000000 /f >NUL 2>&1

:: Keyboard Optimizations
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Data Queue Sizes
reg add "HKLM\System\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "50" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "50" /f >NUL 2>&1

:: Explorer
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v "NoRemoteDestinations" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AltTabSettings" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable Transparency
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Maintenance
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Do not reduce sounds while calling
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f >NUL 2>&1
 
:: Handwriting Telemtry
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Windows Error Reporting
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f >NUL 2>&1 
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Telemetry
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Sleep Study
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: KMS Data sending
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f >NUL 2>&1 

:: Delete Defaultuser0 used during OOBE
net user defaultuser0 /delete >NUL 2>&1 

:: Disable "Administrator" used using OEM
net user administrator /active:no >NUL 2>&1 

::::::::::::
::Internet::
::::::::::::

::Disable Nagle's Algorithm
reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f >NUL 2>&1  
for /f %%s in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s') do set "str=%%i" & if "!str:ServiceName_=!" neq "!str!" (
 	reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >NUL 2>&1
)

:: Set max port to 65535
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "00065534" /f >NUL 2>&1

:: Reduce TIME_WAIT
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000030" /f >NUL 2>&1

:: Disable the TCP autotuning diagnostic tool
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "00000000" /f >NUL 2>&1

:: Enable TCP Extensions for High Performance
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f >NUL 2>&1 

:: Detect congestion fail to receive acknowledgement for a packet within the estimated timeout
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "00000001" /f >NUL 2>&1

:: Set the maximum number of concurrent connections (per server endpoint) allowed when making requests using an HttpClient object.
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "00000016" /f >NUL 2>&1

:: Maximum number of HTTP 1.0 connections to a Web server
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "00000016" /f >NUL 2>&1

:: TCP Congestion Control/Avoidance Algorithm
reg add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >NUL 2>&1

:: QOS
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "00000000" /f >NUL 2>&1
reg add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f >NUL 2>&1

::Network Priorities
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f >NUL 2>&1

::Enable The Network Adapter Onboard Processor
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f >NUL 2>&1

::Netsh
netsh int tcp set heuristics disabled
netsh int tcp set supplemental Internet congestionprovider=ctcp
netsh int tcp set global timestamps=disabled
netsh int tcp set global rsc=disabled
for /f "tokens=1" %%i in ('netsh int ip show interfaces ^| findstr [0-9]') do (
	netsh int ip set interface %%i routerdiscovery=disabled store=persistent
)
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

:::::::::::::::
::Main Tweaks::
:::::::::::::::

:: Enable MSI Mode on USB Controllers
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >NUL 2>&1
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >NUL 2>&1

:: Enable MSI Mode on GPU
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >NUL 2>&1
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >NUL 2>&1

:: Enable MSI Mode on Network Adapters
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >NUL 2>&1
wmic computersystem get manufacturer /format:value| findstr /i /C:VMWare&&goto vmYES
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >NUL 2>&1
goto vmNO

:vmYES
:: Set to Normal Priority
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "2"  /f >NUL 2>&1

:vmNO
:: Enable MSI Mode on Sata controllers
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >NUL 2>&1
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >NUL 2>&1

:: Power Saving
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort"^| findstr "StorPort"') do reg add "%%i" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
for /f "tokens=*" %%i in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr "USB\VID_"') do (
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f >NUL 2>&1
)

:: Import and set the powerplan
powercfg -import "%WINDIR%\Crawen\CrawenOS.pow" 11111111-1111-1111-1111-111111111111 >NUL 2>&1
powercfg /s 11111111-1111-1111-1111-111111111111 && del /f /q "%WINDIR%\Crawen\CrawenOS.pow" >NUL 2>&1
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a >NUL 2>&1
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >NUL 2>&1
powercfg -delete e9a42b02-d5df-448d-aa00-03f14749eb61 >NUL 2>&1

:: Power
if %LAPTOP%==0 (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Storage" /v "StorageD3InModernStandby" /t REG_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "ASPMOptOut" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /t REG_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
	for %%a in (AllowIdleIrpInD3 D3ColdSupported DeviceSelectiveSuspended EnableIdlePowerManagement	EnableSelectiveSuspend
		EnhancedPowerManagementEnabled IdleInWorkingState SelectiveSuspendEnabled SelectiveSuspendOn WaitWakeEnabled 
		WakeEnabled WdfDirectedPowerTransitionEnable) do (
		for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do (
			reg add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >NUL 2>&1
		)
	)
	for %%a in (DisableIdlePowerManagement) do (
		for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do (
			reg add "%%b" /v "%%a" /t REG_DWORD /d "1" /f >NUL 2>&1
		)
	)
) else (
	powercfg /s 381b4222-f694-41f0-9685-ff5bb260df2e >NUL 2>&1
)

:: MEMORY
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%ram%" /f >NUL 2>&1
if %ram% LSS 8000000 (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "33554432" /f >NUL 2>&1
) else if %ram% LSS 16000000 (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "2" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "67108864" /f >NUL 2>&1
) else (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "2" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "2" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "134217728" /f >NUL 2>&1
)

:: Bcdedit
:: HPET
bcdedit /deletevalue useplatformclock > NUL 2>&1
bcdedit /set disabledynamictick yes > NUL 2>&1
bcdedit /set useplatformtick yes > NUL 2>&1

:: BOOT
bcdedit /set bootmenupolicy Legacy
bcdedit /set bootux disabled
bcdedit /set quietboot yes
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000069 true
bcdedit /set {globalsettings} custom:16000069 true

:: OTHER
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set hypervisorlaunchtype off
bcdedit /set {current} description "Crawen"

:: Disable Devices through DevManView
devmanview /disable "System Speaker" MemoryDiagnostic
devmanview /disable "System Timer"
devmanview /disable "UMBus Root Bus Enumerator"
devmanview /disable "Microsoft System Management BIOS Driver"
devmanview /disable "High Precision Event Timer"
devmanview /disable "PCI Encryption/Decryption Controller"
devmanview /disable "AMD PSP"
devmanview /disable "Intel SMBus"
devmanview /disable "Intel Management Engine"
devmanview /disable "PCI Memory Controller"
devmanview /disable "PCI standard RAM Controller"
devmanview /disable "Composite Bus Enumerator"
devmanview /disable "Microsoft Kernel Debug Network Adapter"
devmanview /disable "SM Bus Controller"
devmanview /disable "NDIS Virtual Network Adapter Enumerator"
devmanview /disable "Numeric Data Processor"
devmanview /disable "Microsoft RRAS Root Enumerator"
devmanview /disable "WAN Miniport (IKEv2)"
devmanview /disable "WAN Miniport (IP)"
devmanview /disable "WAN Miniport (IPv6)"
devmanview /disable "WAN Miniport (L2TP)"
devmanview /disable "WAN Miniport (Network Monitor)"
devmanview /disable "WAN Miniport (PPPOE)"
devmanview /disable "WAN Miniport (PPTP)"
devmanview /disable "WAN Miniport (SSTP)"

:: Scheduled Tasks
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

:: Use more privevileges to disable and delete tasks
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" >NUL 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" >NUL 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator" >NUL 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >NUL 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WindowsUpdate" >NUL 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WaaSMedic" >NUL 2>&1

:: Services
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AppVClient" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\CDPSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\CryptSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DispBrokerDesktopSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DsmSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eaphost" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EFS" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\fdPHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\FDResPub" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\IKEEXT" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\InstallService" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\KtmRm" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\lmhosts" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MSDTC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\ShellHWDetection" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SmsRouter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\sppsvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SstpSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WarpJITSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WPDBusEnum" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1

:: Dependencies
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\rdyboost" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1

:: Drivers
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\3ware" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\ADP80XX" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AmdK8" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\arcsas" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AsyncMac" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\bindflt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\buttonconverter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\CAD" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\cdfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\CimFS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\circlass" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\cnghwassist" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\CompositeBus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Dfsc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\ErrDev" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\fdc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\flpydisk" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\fvevol" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb20" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\nvraid" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\rdbss" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\rdyboost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\KSecPkg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb20" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\srv2" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\sfloppy" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SiSRaid2" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SiSRaid4" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Telemetry" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\udfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\umbus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VerifierExt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\vsmraid" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VSTXRAID" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wcnfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WindowsTrustedRTProxy" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

:: Thanks Artanis
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_SZ /d "" /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_SZ /d "" /f >NUL 2>&1

::::::::::::
::CLEANING::
::::::::::::

:: Cleanup after EDGE
sc delete edgeupdate >NUL 2>&1
sc delete edgeupdatem >NUL 2>&1

reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f >NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f >NUL 2>&1
reg delete "HKLM\Software\Classes\MSEdgeHTM" /f >NUL 2>&1
reg delete "HKLM\System\CurrentControlSet\Services\EventLog\Application\edgeupdate" /f >NUL 2>&1
reg delete "HKLM\System\CurrentControlSet\Services\EventLog\Application\edgeupdatem" /f >NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Clients\StartMenuInternet\Microsoft Edge" /f >NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe" /f >NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe" /f >NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Microsoft\EdgeUpdate" /f >NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Microsoft\Edge" /f >NUL 2>&1
reg delete "HKLM\Software\Clients\StartMenuInternet\Microsoft Edge" /f >NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /f >NUL 2>&1

:: Accept Variable
break>C:\Users\Public\success.txt
echo COMPLETED > C:\Users\Public\success.txt

:: ADD Configurator App RunOnce
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "Configurator" /t REG_SZ /d "%WINDIR%\Crawen\Configurator\Configurator.exe" /f >NUL 2>&1

:: Misc Tweaks
lodctr /r >NUL 2>&1
lodctr /r >NUL 2>&1

DEL "%~f0"
exit
