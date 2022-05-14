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

call %WINDIR%\Crawen\7zip.msi /quiet /norestart && del /f /q "%WINDIR%\Crawen\7zip.msi" >NUL 2>&1
NSudoL -ShowWindowMode:hide -Wait -U:T -P:E reg import "%WINDIR%\Crawen\7zip.reg" >NUL 2>&1 && del /f /q "%WINDIR%\Crawen\7zip.reg" >NUL 2>&1
NSudoL -ShowWindowMode:hide -Wait -U:T -P:E reg import "%WINDIR%\Crawen\Services.reg" >NUL 2>&1 && del /f /q "%WINDIR%\Crawen\Services.reg" >NUL 2>&1

:::::::::::::::::::::::::
::Storage Optimizations::
:::::::::::::::::::::::::

:: Storage System
fsutil behavior set memoryusage 2 >NUL 2>&1
fsutil behavior set mftzone 2 >NUL 2>&1
fsutil behavior set allowextchar 0 >NUL 2>&1
fsutil behavior set Bugcheckoncorrupt 0 >NUL 2>&1
fsutil behavior set disable8dot3 1 >NUL 2>&1
fsutil behavior set disablecompression 1 >NUL 2>&1
fsutil behavior set disabledeletenotify 0 >NUL 2>&1
fsutil behavior set disableencryption 1 >NUL 2>&1
fsutil behavior set disablelastaccess 1 >NUL 2>&1
fsutil behavior set encryptpagingfile 0 >NUL 2>&1

:: File System
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Superfetch" /v "StartedComponents" /t reg_DWORD /d "513347" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Superfetch" /v "AdminDisable" /t reg_DWORD /d "8704" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Superfetch" /v "AdminEnable" /t reg_DWORD /d "0" /f >NUL 2>&1

:::::::::::::::::::::::::
::Memory Optimizations:::
:::::::::::::::::::::::::

:: Memory Compression
powershell -Command "Disable-MMAgent -mc"

:: Memory Management
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnablePrefetcher" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t reg_DWORD /d "0" /f >NUL 2>&1

:: Disable Paging
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t reg_DWORD /d "1" /f >NUL 2>&1

:: SvcSplitThreshold
reg add "HKLM\System\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t reg_DWORD /d "%ram%" /f >NUL 2>&1

:: Large System Cache
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t reg_DWORD /d "1" /f >NUL 2>&1
 
:: Speedup Startup
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t reg_DWORD /d "0" /f >NUL 2>&1


:::::::::::::::
::Mitigations::
:::::::::::::::

:: Disable DmaRemapping
for /f %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f DmaRemappingCompatible ^| find /i "Services\" ') do (
	reg add "%%i" /v "DmaRemappingCompatible" /t reg_DWORD /d "0" /f >NUL 2>&1
)

::CSRSS mitigations
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t reg_BINARY /d "222222222222222222222222222222222222222222222222" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t reg_BINARY /d "222222222222222222222222222222222222222222222222" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t reg_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t reg_DWORD /d "3" /f >NUL 2>&1

:: Set System Processes Priority below normal
for %%i in (lsass.exe sppsvc.exe SearchIndexer.exe fontdrvhost.exe sihost.exe ctfmon.exe) do (
  reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%i\PerfOptions" /v "CpuPriorityClass" /t reg_DWORD /d "5" /f
)
:: Set background apps priority below normal
for %%i in (OriginWebHelperService.exe ShareX.exe EpicWebHelper.exe SocialClubHelper.exe steamwebhelper.exe) do (
  reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%i\PerfOptions" /v "CpuPriorityClass" /t reg_DWORD /d "5" /f
)

:: Disable FTH
reg add "HKLM\Software\Microsoft\FTH" /v "Enabled" /t reg_DWORD /d "0" /f >NUL 2>&1

:: Disable Chain Validation
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t reg_DWORD /d "1" /f >NUL 2>&1

:: Correct Mitigation Values
powershell -NoProfile -Command Set-ProcessMitigation -System -Disable CFG >NUL 2>&1
for /f "tokens=3 skip=2" %%a in ('reg query "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do set mitigation_mask=%%a
for /L %%a in (0,1,9) do (
    set mitigation_mask=!mitigation_mask:%%a=2!
)
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t reg_BINARY /d "%mitigation_mask%" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t reg_BINARY /d "%mitigation_mask%" /f >NUL 2>&1

:: not found in ntoskrnl
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t reg_DWORD /d "0" /f >NUL 2>&1

:: Spectre & Meltdown
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t reg_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t reg_DWORD /d "3" /f >NUL 2>&1

:::::::::::::::
::Mitigations::
:::::::::::::::

:: DWM
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Composition" /t reg_DWORD /d "0" /f >NUL 2>&1

:: Security Tweaks 
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "DisableCompression" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "NodeType" /t reg_DWORD /d "2" /f >NUL 2>&1

:: Restrict Windows communication
reg add "HKLM\Software\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t reg_DWORD /d "1" /f

:: Win32PrioritySeparation 26 hex/38 dec
reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t reg_DWORD /d "38" /f >NUL 2>&1

:: Hibernate
powercfg /h off >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t reg_DWORD /d "0" /f >NUL 2>&1

:: MMCSS
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t reg_DWORD /d "10" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t reg_DWORD /d "10" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t reg_DWORD /d "10000" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t reg_SZ /d "True" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "NoLazyMode" /t reg_DWORD /d "1" /f >NUL 2>&1

:: Hung Apps, Delay
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t reg_SZ /d "1" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t reg_SZ /d "1000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t reg_SZ /d "8" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t reg_SZ /d "2000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t reg_BINARY /d "9A12038010000000" /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t reg_DWORD /d "100" /f >NUL 2>&1

:: Enable Hardware Accelerated Scheduling (HAGS)
reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t reg_DWORD /d "2" /f >NUL 2>&1

:: Mouse Optimizations
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t reg_SZ /d "10" /f >NUL 2>&1
reg add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t reg_SZ /d "0" /f >NUL 2>&1
reg add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t reg_SZ /d "0" /f >NUL 2>&1
reg add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t reg_SZ /d "0" /f >NUL 2>&1
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t reg_BINARY /d 0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000 /f >NUL 2>&1
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t reg_BINARY /d 0000000000000000000038000000000000007000000000000000A800000000000000E00000000000 /f >NUL 2>&1

:: Keyboard Optimizations
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t reg_DWORD /d "0" /f >NUL 2>&1

:: Data Queue Sizes
reg add "HKLM\System\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t reg_DWORD /d "50" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t reg_DWORD /d "50" /f >NUL 2>&1

:: Disable Transparency
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t reg_DWORD /d "0" /f >NUL 2>&1

:: Disable Maintenance
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t reg_DWORD /d "1" /f >NUL 2>&1

:: Do not reduce sounds while calling
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t reg_DWORD /d "3" /f >NUL 2>&1
 
:: Handwriting Telemtry
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t reg_DWORD /d "1" /f >NUL 2>&1

:: Windows Error Reporting
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t reg_DWORD /d "1" /f >NUL 2>&1 
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t reg_DWORD /d "0" /f >NUL 2>&1

:: Telemetry
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowDeviceNameInTelemetry" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t reg_DWORD /d "0" /f >NUL 2>&1

:: Disable Sleep Study
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t reg_DWORD /d "1" /f >NUL 2>&1

:: KMS Data sending
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t reg_DWORD /d "1" /f >NUL 2>&1 

:: Delete Defaultuser0 used during OOBE
net user defaultuser0 /delete >NUL 2>&1 

:: Disable "Administrator" used using OEM
net user administrator /active:no >NUL 2>&1 

::::::::::::
::Internet::
::::::::::::

::Disable Nagle's Algorithm
reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t reg_DWORD /d "00000001" /f >NUL 2>&1  
for /f %%s in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s') do set "str=%%i" & if "!str:ServiceName_=!" neq "!str!" (
 	reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TCPNoDelay" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpAckFrequency" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpDelAckTicks" /t reg_DWORD /d "0" /f >NUL 2>&1
)

:: Set max port to 65535
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t reg_DWORD /d "00065534" /f >NUL 2>&1

:: Reduce TIME_WAIT
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t reg_DWORD /d "00000030" /f >NUL 2>&1

:: Disable the TCP autotuning diagnostic tool
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t reg_DWORD /d "00000000" /f >NUL 2>&1

:: Enable TCP Extensions for High Performance
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t reg_DWORD /d "00000001" /f >NUL 2>&1 

:: Detect congestion fail to receive acknowledgement for a packet within the estimated timeout
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t reg_DWORD /d "00000001" /f >NUL 2>&1

:: Set the maximum number of concurrent connections (per server endpoint) allowed when making requests using an HttpClient object.
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t reg_DWORD /d "00000016" /f >NUL 2>&1

:: Maximum number of HTTP 1.0 connections to a Web server
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t reg_DWORD /d "00000016" /f >NUL 2>&1

:: TCP Congestion Control/Avoidance Algorithm
reg add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t reg_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t reg_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >NUL 2>&1

:: QOS
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t reg_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t reg_DWORD /d "00000000" /f >NUL 2>&1
reg add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t reg_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t reg_DWORD /d "0" /f >NUL 2>&1

::Network Priorities
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t reg_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t reg_DWORD /d "5" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t reg_DWORD /d "6" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t reg_DWORD /d "7" /f >NUL 2>&1

::Enable The Network Adapter Onboard Processor
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t reg_DWORD /d "0" /f >NUL 2>&1

::Netsh
netsh int tcp set heuristics disabled
netsh int tcp set supplemental Internet congestionprovider=ctcp
netsh int tcp set global timestamps=disabled
netsh int tcp set global rsc=disabled
for /f "tokens=1" %%i in ('netsh int ip show interfaces ^| findstr [0-9]') do (
	netsh int ip set interface %%i routerdiscovery=disabled store=persistent
)
powershell -NoProfile -Command "Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6, ms_msclient, ms_pacer, ms_server" >NUL 2>&1

:: NIC Settings - imbiriy
for /f %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (
    for /f %%i in ('reg query "%%a" /v "*ReceiveBuffers" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*ReceiveBuffers" /t reg_SZ /d "1024" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TransmitBuffers" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TransmitBuffers" /t reg_SZ /d "1024" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*DeviceSleepOnDisconnect" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*DeviceSleepOnDisconnect" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*EEE" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*ModernStandbyWoLMagicPacket" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*ModernStandbyWoLMagicPacket" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*SelectiveSuspend" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*SelectiveSuspend" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnMagicPacket" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*WakeOnMagicPacket" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnPattern" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*WakeOnPattern" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AutoPowerSaveModeEnabled" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EEELinkAdvertisement" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EEELinkAdvertisement" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EeePhyEnable" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EeePhyEnable" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableGreenEthernet" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableModernStandby" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableModernStandby" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (
        reg add "%%i" /v "GigaLite" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PowerDownPll" ^| findstr "HKEY"') do (
        reg add "%%i" /v "PowerDownPll" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (
        reg add "%%i" /v "PowerSavingMode" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ReduceSpeedOnPowerDown" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "S5WakeOnLan" ^| findstr "HKEY"') do (
        reg add "%%i" /v "S5WakeOnLan" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "SavePowerNowEnabled" ^| findstr "HKEY"') do (
        reg add "%%i" /v "SavePowerNowEnabled" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ULPMode" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnLink" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeOnLink" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnSlot" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeOnSlot" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeUpModeCap" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeUpModeCap" /t reg_SZ /d "0" /f >NUL 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeUpModeCap" ^| findstr "HKEY"') do (
        reg add "%%i" /v "PnPCapabilities" /t reg_SZ /d "24" /f >NUL 2>&1
    )
) >NUL 2>&1

:::::::::::::::
::Main Tweaks::
:::::::::::::::

:: Enable MSI Mode on USB Controllers
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t reg_DWORD /d "1" /f >NUL 2>&1
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >NUL 2>&1

:: Enable MSI Mode on GPU
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t reg_DWORD /d "1" /f >NUL 2>&1
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >NUL 2>&1

:: Enable MSI Mode on Network Adapters
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t reg_DWORD /d "1" /f >NUL 2>&1
wmic computersystem get manufacturer /format:value| findstr /i /C:VMWare&&goto vmYES
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >NUL 2>&1
goto vmNO

:vmYES
:: Set to Normal Priority
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t reg_DWORD /d "2"  /f >NUL 2>&1

:vmNO
:: Enable MSI Mode on Sata controllers
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t reg_DWORD /d "1" /f >NUL 2>&1
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >NUL 2>&1


:: Power Saving
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort"^| findstr "StorPort"') do reg add "%%i" /v "EnableIdlePowerManagement" /t reg_DWORD /d "0" /f >NUL 2>&1
for /f "tokens=*" %%i in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr "USB\VID_"') do (
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t reg_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t reg_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t reg_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t reg_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t reg_DWORD /d "0" /f >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t reg_DWORD /d "0" /f >NUL 2>&1 >NUL 2>&1
 reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t reg_DWORD /d "0" /f >NUL 2>&1
)

:: Import and set the powerplan
powercfg -import "%WINDIR%\Crawen\CrawenOS.pow" 11111111-1111-1111-1111-111111111111 >NUL 2>&1
powercfg /s 11111111-1111-1111-1111-111111111111 && del /f /q "%WINDIR%\Crawen\CrawenOS.pow" >NUL 2>&1
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a >NUL 2>&1
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >NUL 2>&1
powercfg -delete e9a42b02-d5df-448d-aa00-03f14749eb61 >NUL 2>&1

:: Power
if %LAPTOP%==0 (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Storage" /v "StorageD3InModernStandby" /t reg_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t reg_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "ASPMOptOut" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /t reg_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t reg_DWORD /d "1" /f
	for %%a in (AllowIdleIrpInD3 D3ColdSupported DeviceSelectiveSuspended EnableIdlePowerManagement	EnableSelectiveSuspend
		EnhancedPowerManagementEnabled IdleInWorkingState SelectiveSuspendEnabled SelectiveSuspendOn WaitWakeEnabled 
		WakeEnabled WdfDirectedPowerTransitionEnable) do (
		for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do (
			reg add "%%b" /v "%%a" /t reg_DWORD /d "0" /f >NUL 2>&1
		)
	)
	for %%a in (DisableIdlePowerManagement) do (
		for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do (
			reg add "%%b" /v "%%a" /t reg_DWORD /d "1" /f >NUL 2>&1
		)
	)
) else (
	powercfg /s 381b4222-f694-41f0-9685-ff5bb260df2e >NUL 2>&1
)

:: MEMORY
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t reg_DWORD /d "%ram%" /f >NUL 2>&1
if %ram% LSS 8000000 (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t reg_DWORD /d "33554432" /f >NUL 2>&1
) else if %ram% LSS 16000000 (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t reg_DWORD /d "2" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t reg_DWORD /d "67108864" /f >NUL 2>&1
) else (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t reg_DWORD /d "1" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t reg_DWORD /d "2" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t reg_DWORD /d "2" /f >NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t reg_DWORD /d "134217728" /f >NUL 2>&1
)

:: BCDEDIT
bcdedit /deletevalue useplatformclock > NUL 2>&1
bcdedit /set disabledynamictick yes > NUL 2>&1
bcdedit /set useplatformtick yes > NUL 2>&1
bcdedit /timeout 10 > NUL 2>&1
bcdedit /set bootmenupolicy standard > NUL 2>&1
bcdedit /set hypervisorlaunchtype off > NUL 2>&1
bcdedit /set tpmbootentropy ForceDisable > NUL 2>&1
bcdedit /set quietboot yes > NUL 2>&1
bcdedit /set {current} description Crawen

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
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\AppID\EDP Policy Manager" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\AppID\PolicyConverter" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\InstallService\SmartRetry" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\LanguageComponentsInstaller\Installation" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\ApplicationData\appuriverifierinstall" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskregistrationMaintenanceTask" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\CertificateServicesClient\KeyPregenTask" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Clip\License Validation" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleCommand" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleWnsCommand" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\IntegrityCheck" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\LocateCommandUserSession" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\registerDeviceAccountChange" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\registerDeviceLocationRightsChange" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\registerDevicePeriodic24" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\registerDevicePolicyChange" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\registerDeviceProtectionStateChanged" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\registerDeviceSettingChange" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\DeviceDirectoryClient\registerUserDevice" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Management\Provisioning\Cellular" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\MUI\LPRemove" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" >nul 2>&
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\USB\Usb-Notifications" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\Windows\Wininet\CacheTask" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /change /disable /TN "\Microsoft\XblGameSave\XblGameSaveTask" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\PLA\System" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\PLA" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WindowsUpdate" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\WaaSMedic" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\RetailDemo" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\SyncCenter" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\TaskScheduler" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\Windows Activation Technologies" >nul 2>&1
NSudoL -ShowWindowMode:hide -U:T -P:E schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" >nul 2>&1


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
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "Configurator" /t reg_SZ /d "%WINDIR%\Crawen\Configurator\Configurator.exe" /f >NUL 2>&1

:: Misc Tweaks
lodctr /r >NUL 2>&1
lodctr /r >NUL 2>&1

DEL "%~f0"
exit
