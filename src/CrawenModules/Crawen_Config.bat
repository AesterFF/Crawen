@echo off
SETLOCAL EnableDelayedExpansion

>nul 2>nul "%WinDir%\System32\cacls.exe" "%WinDir%\System32\config\system"

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

:: PC
set /a PC=TRUE
if %CHASSISTYPE% GTR 7 ( 
	if %CHASSISTYPE% LSS 17 ( set /a PC=FALSE )
    if %CHASSISTYPE% GTR 28 ( set /a PC=FALSE )
)

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
)
) >NUL 2>&1

for %%a in (DisableIdlePowerManagement) do (
for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do (
reg add "%%b" /v "%%a" /t REG_DWORD /d "1" /f
)
) >NUL 2>&1
) else (
powercfg /s 381b4222-f694-41f0-9685-ff5bb260df2e
)

:PROGRAMS
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
