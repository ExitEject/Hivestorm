# Check for common misconfigurations:

# Check if Windows Defender real-time monitoring is disabled
$defender_disabled = Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring

# Check if Windows Firewall is disabled for all profiles
$firewall_disabled = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}

# Alert and force-enable Windows Defender real-time monitoring if disabled
if ($defender_disabled -eq $true) {
    Write-Host "Windows Defender is disabled. Attempting to enable..." -ForegroundColor Yellow
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Host "Windows Defender real-time monitoring has been enabled." -ForegroundColor Green
} else {
    Write-Host "Windows Defender real-time monitoring is already enabled." -ForegroundColor Green
}

# Alert and force-enable Windows Firewall if disabled for any profile
if ($firewall_disabled) {
    Write-Host "Windows Firewall is disabled. Attempting to enable for all profiles..." -ForegroundColor Yellow
    # Enable Windows Firewall for all profiles (Domain, Private, Public)
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Write-Host "Windows Firewall has been enabled for all profiles." -ForegroundColor Green
} else {
    Write-Host "Windows Firewall is already enabled for all profiles." -ForegroundColor Green
}

# Attempt to start the Windows Defender service if it's not running
Start-Service -Name WinDefend -ErrorAction SilentlyContinue

# Verify if the Windows Defender service is running
$service = Get-Service -Name WinDefend
if ($service.Status -eq 'Running') {
    Write-Host "Windows Defender service is running." -ForegroundColor Green
} else {
    Write-Host "Failed to start Windows Defender service." -ForegroundColor Red
}
