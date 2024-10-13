# Get the "Administrators" group
$adminGroup = [ADSI]"WinNT://./Administrators,group"

# Define current local users
$current_users = @"
Administrator
pink
brown
cyan
yellow
green
coral
black
white
blue
orange
tan
purple
red
lime
POLUS$
MIRA$
"@ -split "\r?\n" | ForEach-Object { $_.Trim() }

# Define allowed local users
$allowed_users = @"
cyan
red
white
pink
blue
green
brown
purple
orange
lime
yellow
black
"@ -split "\r?\n" | ForEach-Object { $_.Trim() }

# Find unauthorized users (not in the allowed_users list)
$unauthorized_users = $current_users | Where-Object { $_ -notin $allowed_users }

# Function to remove unauthorized users
function Remove-UnauthorizedUsers {
    param (
        [string[]]$unauthorized_users
    )

    foreach ($user in $unauthorized_users) {
        try {
            Write-Host "Attempting to remove user account: $user" -ForegroundColor Yellow
            # Remove the user account
            net user $user /delete
            Write-Host "Successfully removed user account: $user" -ForegroundColor Green
        } catch {
            Write-Host "Error removing user account $user $_" -ForegroundColor Red
        }
    }
}

# Call the function to remove unauthorized users
Remove-UnauthorizedUsers -unauthorized_users $unauthorized_users

# Define allowed admins
$allowed_admins = @"
cyan
red
white
pink
"@ -split "\r?\n" | ForEach-Object { $_.Trim() }

# Function to ensure authorized users are in Administrators group
function Add-Admins {
    param (
        [string[]]$authorized_users,
        $adminGroup
    )

    foreach ($user in $authorized_users) {
        try {
            # Check if user is already in the Administrators group
            $isMember = $adminGroup.psbase.Invoke("Members") | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) } | Where-Object { $_ -eq $user }

            if (-not $isMember) {
                Write-Host "Adding $user to Administrators group" -ForegroundColor Yellow
                $adminGroup.Add("WinNT://./$user,user")
                Write-Host "Successfully added $user to Administrators group" -ForegroundColor Green
            } else {
                Write-Host "$user is already in the Administrators group." -ForegroundColor Green
            }
        } catch {
            Write-Host "Failed to add $user to Administrators group: $_" -ForegroundColor Red
        }
    }
}

# Ensure authorized users are in the Administrators group
Write-Host "Ensuring authorized users are in the Administrators group..." -ForegroundColor Cyan
Add-Admins -authorized_users $allowed_admins -adminGroup $adminGroup

# Define the list of services to check and restart if stopped
$services = @("wuauserv", "TermService", "Dnscache")

# Loop through each service in the list
foreach ($serviceName in $services) {
    # Get the status of the service
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($service) {
        # Check if the service is stopped
        if ($service.Status -eq 'Stopped') {
            Write-Output "Service '$serviceName' is stopped. Attempting to start..."
            # Try to start the service
            try {
                Start-Service -Name $serviceName
                Write-Output "Service '$serviceName' started successfully."
            } catch {
                Write-Output "Failed to start service '$serviceName'. Error: $_"
            }
        } else {
            Write-Output "Service '$serviceName' is already running."
        }
    } else {
        Write-Output "Service '$serviceName' not found on this system."
    }
}

# Enforce password complexity on local accounts
Write-Host "Enforcing strong password policies for local accounts..." -ForegroundColor Green

# Define local security policy parameters
$localPolicy = @(
    @{ Name = 'MinimumPasswordLength'; Value = 12 },        # Minimum length of 12 characters
    @{ Name = 'PasswordComplexity'; Value = 1 },            # Enforce password complexity (1: enabled, 0: disabled)
    @{ Name = 'MinimumPasswordAge'; Value = 1 },            # Minimum password age of 1 day
    @{ Name = 'MaximumPasswordAge'; Value = 60 },           # Maximum password age of 60 days
    @{ Name = 'PasswordHistorySize'; Value = 24 },          # Remember last 24 passwords (prevents reuse)
    @{ Name = 'LockoutBadCount'; Value = 5 },               # Lock out after 5 failed attempts
    @{ Name = 'LockoutDuration'; Value = 30 },              # Lockout duration of 30 minutes
    @{ Name = 'LockoutObservationWindow'; Value = 30 }      # Failed attempt count reset after 30 minutes
)

foreach ($policy in $localPolicy) {
    secedit /export /cfg "$env:TEMP\secpol.cfg"
    (Get-Content "$env:TEMP\secpol.cfg") -replace "($($policy.Name)=).*", "`$1$($policy.Value)" | Set-Content "$env:TEMP\secpol.cfg"
    secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY
    Remove-Item "$env:TEMP\secpol.cfg"
}

Write-Host "Password policy for local accounts enforced successfully." -ForegroundColor Green

# Disable the Guest account
try {
    net user Guest /active:no
    Write-Host "Guest account disabled." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Guest account: $_" -ForegroundColor Red
}

# Disable the Administrator account
try {
    net user Administrator /active:no
    Write-Host "Administrator account disabled." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Administrator account: $_" -ForegroundColor Red
} 

# Stop and disable Remote Registry service
Set-Service -Name "RemoteRegistry" -StartupType Disabled
Stop-Service -Name "RemoteRegistry"

# Disable SMB 1.x
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

# Enable Network Level Authentication (NLA) for RDP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

# Ensure that Remote Desktop connections are allowed
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

# Enable Remote Desktop in the Windows Firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

Write-Host "Network Level Authentication has been enabled for Remote Desktop." -ForegroundColor Green
