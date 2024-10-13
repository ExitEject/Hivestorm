# Import the Active Directory module
Import-Module ActiveDirectory

# Get the domain distinguished name
$domainDN = (Get-ADDomain).DistinguishedName

# Get the "Administrators" group from the Builtin container
$adminGroup = Get-ADGroup -Filter { Name -eq "Administrators" } -SearchBase "CN=Builtin,$domainDN"

# Define current users (e.g., from the Administrators group or a list)
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

# Define allowed users
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
            # Remove the user account from Active Directory
            Remove-ADUser -Identity $user -Confirm:$false -ErrorAction Stop
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

# Function to ensure authorized users are in Remote Desktop Users group
# Function to ensure authorized users are in Remote Desktop Users group
function Add-RDPAccess-AD {
    param (
        [string[]]$authorized_users,
        $adGroup
    )

    foreach ($user in $authorized_users) {
        try {
            # Check if user is already in the RDP AD group
            $isMember = Get-ADGroupMember -Identity $adGroup.DistinguishedName -Recursive | Where-Object { $_.SamAccountName -eq $user }

            if (-not $isMember) {
                Write-Host "Adding $user to $($adGroup.Name) group for RDP access" -ForegroundColor Yellow
                Add-ADGroupMember -Identity $adGroup.DistinguishedName -Members $user -ErrorAction Stop
                Write-Host "Successfully added $user to $($adGroup.Name) group" -ForegroundColor Green
            } else {
                Write-Host "$user already has RDP access in $($adGroup.Name)." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Failed to add $user to $($adGroup.Name) group: $($_)" -ForegroundColor Red
        }
    }
}

# Get the "Remote Desktop Users" group from the Builtin container
$rdpADGroup = Get-ADGroup -Filter { Name -eq "Remote Desktop Users" } -SearchBase "CN=Builtin,$domainDN"

# Ensure authorized users have RDP access
Write-Host "`nEnsuring authorized users have RDP access..." -ForegroundColor Cyan
Add-RDPAccess-AD -authorized_users $allowed_users -adGroup $rdpADGroup
# Function to remove unauthorized admin privileges and verify removal with logging
function Remove-UnauthorizedAdminPrivileges {
    param (
        [string[]]$unauthorized_admins
    )

    foreach ($admin in $unauthorized_admins) {
        try {
            Write-Host "Attempting to remove admin privileges from account: $admin" -ForegroundColor Yellow

            # Remove the user from the Administrators group
            Remove-ADGroupMember -Identity $adminGroup.DistinguishedName -Members $admin -Confirm:$false -ErrorAction Stop

            # Verification: Check if the user is still in the Administrators group
            $isMember = Get-ADGroupMember -Identity $adminGroup.DistinguishedName -Recursive | Where-Object { $_.SamAccountName -eq $admin }

            if ($isMember) {
                Write-Host "Failed to remove admin privileges from: $admin" -ForegroundColor Red
            } else {
                Write-Host "Successfully removed admin privileges from: $admin" -ForegroundColor Green
            }
        }
        catch {
            Write-Host ("Error removing admin privileges from $admin`: $_") -ForegroundColor Red
        }
    }
}

# Function to check if a user is in the Administrators group
function Is-UserAdmin {
    param (
        [string]$username
    )

    try {
        $isMember = Get-ADGroupMember -Identity $adminGroup.DistinguishedName -Recursive | Where-Object { $_.SamAccountName -eq $username }
        return $null -ne $isMember
    }
    catch {
        return $false
    }
}

# Find unauthorized users (not in the allowed_users list)
$unauthorized_users = $current_users | Where-Object { $_ -notin $allowed_users }

# Print unauthorized users
if ($unauthorized_users) {
    Write-Host "Unauthorized users:" -ForegroundColor Cyan
    $unauthorized_users | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No unauthorized users found." -ForegroundColor Green
}

# Find current admins (users in the Administrators group)
$current_admins = $current_users | Where-Object { Is-UserAdmin $_ }

# Find unauthorized admins (in Administrators group but not in allowed_admins)
$unauthorized_admins = $current_admins | Where-Object { $_ -notin $allowed_admins }

# Print unauthorized admins
if ($unauthorized_admins) {
    Write-Host "`nUnauthorized admins:" -ForegroundColor Cyan
    $unauthorized_admins | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "`nNo unauthorized admins found." -ForegroundColor Green
}

# Function to remove unauthorized admin privileges and verify removal with logging
function Remove-UnauthorizedAdminPrivileges2 {
    param (
        [string[]]$unauthorized_admins
    )
    
    # Define administrative groups
    $adminGroups = @(
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators"
    )

    foreach ($admin in $unauthorized_admins) {
        foreach ($group in $adminGroups) {
            try {
                Write-Host "Attempting to remove '$admin' from group '$group'" -ForegroundColor Yellow
                
                # Remove the user from the admin group
                Remove-ADGroupMember -Identity $group -Members $admin -Confirm:$false -ErrorAction Stop
                
                Write-Host "Removed '$admin' from group '$group'" -ForegroundColor Green
            } catch {
                # Handle errors if the user is not a member of the group
                if ($_.Exception.Message -notmatch "is not a member") {
                    Write-Host "Error removing '$admin' from group '$group': $_" -ForegroundColor Red
                } else {
                    Write-Host "'$admin' is not a member of '$group'" -ForegroundColor Cyan
                }
            }
        }
    }
}
Remove-UnauthorizedAdminPrivileges2 -unauthorized_admins $unauthorized_admins


# Ensure authorized users have RDP access
Write-Host "`nEnsuring authorized users have RDP access..." -ForegroundColor Cyan
Add-RDPAccess-AD -authorized_users $allowed_users -adGroup $rdpADGroup

# Define the list of services you want to check and restart if stopped
$services = @("DNS", "Remote Desktop Services", "NTDS") # Replace with your desired services

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

# Enforce strong password policies for AD accounts
Write-Host "Enforcing strong password policies for AD accounts in domain: $domainDN..."

# Modify the default domain password policy
Set-ADDefaultDomainPasswordPolicy `
    -Identity $domainDN `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge 60.00:00:00 `
    -MinPasswordAge 1.00:00:00 `
    -LockoutThreshold 5 `
    -LockoutDuration 00:30:00 `
    -LockoutObservationWindow 00:30:00

Write-Host "Password policy for AD accounts enforced successfully."

# Disable the Guest account
Disable-ADAccount -Identity "Guest"

# Disable the Administrator account
Disable-ADAccount -Identity "Administrator"

$currentUser = $env:USERNAME

function New-RandomPassword {
    param([int]$length = 15)
    # Define character sets
    $lowerChars = 'abcdefghijkmnopqrstuvwxyz'
    $upperChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $digits = '23456789'
    $specialChars = '!@#$%^&*()'
    $allChars = $lowerChars + $upperChars + $digits + $specialChars

    do {
        # Ensure the password includes at least one character from each category
        $passwordChars = @()
        $passwordChars += ($lowerChars | Get-Random)
        $passwordChars += ($upperChars | Get-Random)
        $passwordChars += ($digits | Get-Random)
        $passwordChars += ($specialChars | Get-Random)

        # Fill the remaining length with random characters from all categories
        for ($i = 1; $i -le ($length - 4); $i++) {
            $passwordChars += ($allChars | Get-Random)
        }

        # Shuffle the password to randomize character positions
        $password = ($passwordChars | Get-Random -Count $passwordChars.Count) -join ''

        # Test if password meets complexity requirements
        $meetsComplexity = ($password -match '[a-z]') -and ($password -match '[A-Z]') -and ($password -match '\d') -and ($password -match '[!@#$%^&*()]')
    } while (-not $meetsComplexity)

    return $password
}

# Exclude built-in accounts and service accounts
$excludeUsers = @('Administrator', 'krbtgt', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')

Get-ADUser -Filter * | Where-Object { 
    $_.SamAccountName -ne $currentUser -and 
    -not ($excludeUsers -contains $_.SamAccountName) 
} | ForEach-Object {
    $user = $_

    # Initialize variables for password reset attempts
    $maxRetries = 5
    $retryCount = 0
    $passwordResetSuccess = $false

    do {
        # Generate a new password
        $newPassword = New-RandomPassword 15
        $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force

        try {
            # Reset password
            Set-ADAccountPassword -Identity $user -Reset -NewPassword $securePassword -ErrorAction Stop
            $passwordResetSuccess = $true
            Write-Host "Password for user $($user.SamAccountName) has been reset."
        } catch {
            if ($_ -match 'password does not meet the length, complexity, or history requirement') {
                if ($retryCount -lt $maxRetries) {
                    $retryCount++
                    Write-Host "Password reset failed due to password history. Retrying ($retryCount/$maxRetries)..."
                } else {
                    Write-Host "Failed to reset password for user $($user.SamAccountName) after $maxRetries attempts."
                    $passwordResetSuccess = $false
                    break
                }
            } else {
                Write-Host "Failed to reset password for user $($user.SamAccountName): $_"
                $passwordResetSuccess = $false
                break
            }
        }
    } while (-not $passwordResetSuccess)

    if ($passwordResetSuccess) {
        # Set 'PasswordNeverExpires' to false
        try {
            Set-ADUser -Identity $user -PasswordNeverExpires $false -ErrorAction Stop
        } catch {
            Write-Host "Failed to set 'PasswordNeverExpires' for user $($user.SamAccountName): $_"
        }

        # Set 'ChangePasswordAtLogon' to true
        try {
            Set-ADUser -Identity $user -ChangePasswordAtLogon $true -ErrorAction Stop
        } catch {
            Write-Host "Failed to set 'ChangePasswordAtLogon' for user $($user.SamAccountName): $_"
        }
    }
}

# Define the date threshold for stale passwords (e.g., 90 days ago)
$thresholdDate = (Get-Date).AddDays(-90)

# Initialize arrays to hold users
$usersWithNoPasswordRequired = @()
$usersWithPasswordNeverExpires = @()
$stalePasswordUsers = @()
$usersMustChangePassword = @()
$usersWithReversibleEncryption = @()

# Get all user accounts
$allUsers = Get-ADUser -Filter * -Properties SamAccountName, PasswordNotRequired, PasswordNeverExpires, PasswordLastSet, PasswordExpired, AllowReversiblePasswordEncryption

foreach ($user in $allUsers) {
    # Check for 'PasswordNotRequired'
    if ($user.PasswordNotRequired) {
        $usersWithNoPasswordRequired += $user
    }

    # Check for 'PasswordNeverExpires'
    if ($user.PasswordNeverExpires) {
        $usersWithPasswordNeverExpires += $user
    }

    # Check for stale passwords
    if ($user.PasswordLastSet -lt $thresholdDate) {
        $stalePasswordUsers += $user
    }

    # Check for 'PasswordExpired'
    if ($user.PasswordExpired) {
        $usersMustChangePassword += $user
    }

    # Check for 'AllowReversiblePasswordEncryption'
    if ($user.AllowReversiblePasswordEncryption) {
        $usersWithReversibleEncryption += $user
    }
}

# Display results
Write-Host "Users with 'PasswordNotRequired' set to True:"
$usersWithNoPasswordRequired | Select-Object SamAccountName

Write-Host "`nUsers with 'PasswordNeverExpires' set to True:"
$usersWithPasswordNeverExpires | Select-Object SamAccountName

Write-Host "`nUsers who haven't changed passwords since $thresholdDate`:"
$stalePasswordUsers | Select-Object SamAccountName, PasswordLastSet

Write-Host "`nUsers who must change password at next logon:"
$usersMustChangePassword | Select-Object SamAccountName

Write-Host "`nUsers with 'AllowReversiblePasswordEncryption' set to True:"
$usersWithReversibleEncryption | Select-Object SamAccountName

try {
    # Define the registry path and value name
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "DisableCAD"
    $desiredValue = 0

    # Check if the registry path exists; if not, create it
    if (-not (Test-Path $registryPath)) {
        Write-Output "Registry path not found. Creating path: $registryPath"
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the current value of DisableCAD
    $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

    if ($currentValue.$valueName -ne $desiredValue) {
        # Set DisableCAD to 0 to require CTRL+ALT+DEL
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue
        Write-Output "Successfully updated '$valueName' to '$desiredValue'. CTRL+ALT+DEL is now required at logon."

        # Optionally, you can force a policy update
        Write-Output "Updating group policy settings..."
        gpupdate /force | Out-Null
        Write-Output "Group policy updated successfully."
    }
    else {
        Write-Output "'$valueName' is already set to '$desiredValue'. No changes are necessary."
    }
}
catch {
    Write-Error "An error occurred: $_"
}

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

# Define the list of authorized shares
$AuthorizedShares = @(
    "C$",
    "ADMIN$",
    "IPC$"
    # Add other authorized shares here, e.g., "SharedDocs"
)

# Define default shares to exclude from removal
$DefaultShares = @(
    "C$",
    "ADMIN$",
    "IPC$",
    "NETLOGON",
    "SYSVOL"
    # Add other default shares that should never be removed
)

# Retrieve all current shares using CIM (recommended over WMI)
try {
    $CurrentShares = Get-CimInstance -ClassName Win32_Share
} catch {
    Write-Error "Failed to retrieve current shares: $_"
    exit
}

# Iterate through each share and identify unauthorized ones
foreach ($share in $CurrentShares) {
    $shareName = $share.Name

    # Skip default shares
    if ($DefaultShares -contains $shareName) {
        Write-Output "Default share present: '$shareName'. No action taken."
        continue
    }

    # Check if the share is authorized
    if (-not ($AuthorizedShares -contains $shareName)) {
        Write-Output "Unauthorized share detected: '$shareName'. Attempting to remove..."

        try {
            # Remove the unauthorized share using CIM method
            $deleteResult = Invoke-CimMethod -InputObject $share -MethodName Delete

            if ($deleteResult.ReturnValue -eq 0) {
                Write-Output "Successfully removed share: '$shareName'."
            } else {
                Write-Warning "Failed to remove share: '$shareName'. ReturnValue: $($deleteResult.ReturnValue)"
            }
        } catch {
            Write-Error "Error removing share '$shareName': $_"
        }
    } else {
        Write-Output "Authorized share present: '$shareName'. No action taken."
    }
}

Write-Output "Share cleanup process completed."

### Part 1: Stop and Disable the Microsoft FTP Service ###

# Define the service name
$badserviceName = "FTPSVC"

# Check if the service exists
$ftpService = Get-Service -Name $badserviceName -ErrorAction SilentlyContinue

if ($ftpService) {
    # Stop the service if it's running
    if ($ftpService.Status -ne 'Stopped') {
        Stop-Service -Name $badserviceName -Force
        Write-Host "FTP Service stopped."
    }

    # Disable the service
    Set-Service -Name $badserviceName -StartupType Disabled
    Write-Host "FTP Service disabled."
} else {
    Write-Host "FTP Service not found on this system."
}

### Part 2: Configure Automatic Windows Updates ###

# Define the registry path for Windows Update policies
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"

# Create the registry key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set Automatic Updates to auto-download and schedule the install (Option 4)
Set-ItemProperty -Path $regPath -Name "AUOptions" -Value 4 -Type DWord

# Enable Automatic Updates
Set-ItemProperty -Path $regPath -Name "NoAutoUpdate" -Value 0 -Type DWord

# Include updates for other Microsoft products
Set-ItemProperty -Path $regPath -Name "IncludeRecommendedUpdates" -Value 1 -Type DWord

Write-Host "Automatic Updates configured to auto-download and schedule installation."

# Set the path to cyan's desktop
$desktopPath = "C:\Users\cyan\Desktop"
# Set the filename of the CCleaner executable
$ccleanerExe = "CCleaner64.exe"
# Combine the path and filename
$ccleanerPath = Join-Path $desktopPath $ccleanerExe

# Check if the file exists
if (Test-Path $ccleanerPath) {
    # Delete the CCleaner executable
    Remove-Item $ccleanerPath -Force
    Write-Host "CCleaner executable deleted from desktop."
} else {
    Write-Host "CCleaner executable not found on desktop."
}

# Define the registry path for Chrome policies
$registryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"

# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    try {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Host "Created registry key: $registryPath"
    } catch {
        Write-Error "Failed to create registry key: $_"
        exit 1
    }
}

# Set the AdsSettingForIntrusiveAdsSites policy to block ads (value 2)
try {
    Set-ItemProperty -Path $registryPath -Name "AdsSettingForIntrusiveAdsSites" -Value 2 -Type DWord
    Write-Host "Successfully set AdsSettingForIntrusiveAdsSites to block intrusive ads."
} catch {
    Write-Error "Failed to set the policy: $_"
    exit 1
}

# Inform the user that Chrome needs to be restarted
Write-Host "Please restart Google Chrome for the changes to take effect."

# Enable NLA for RDP Connections

# Path to the registry key for RDP settings
$RdpTcpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

# Enable NLA by setting UserAuthentication to 1
Set-ItemProperty -Path $RdpTcpRegPath -Name "UserAuthentication" -Value 1

# Ensure that Remote Desktop connections are allowed
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

# Enable Remote Desktop in the Windows Firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

Write-Host "Network Level Authentication has been enabled for Remote Desktop."

#################################TEST CODE##################################
# Stop and disable Remote Registry service
Set-Service -Name "RemoteRegistry" -StartupType Disabled
Stop-Service -Name "RemoteRegistry"

# Validate heap integrity setting (enable it)
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "DisableHeapLookaside" -Value 1 -PropertyType DWord -Force

# Disable AutoPlay for all users
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# IIS: Require SSL connections
Import-Module WebAdministration
Set-WebConfigurationProperty -Filter "system.webServer/security/access" -Name "sslFlags" -Value "Ssl" -PSPath "IIS:\"

# PHP: Disable display errors (if PHP is installed)
if (Test-Path "HKLM:\SOFTWARE\PHP") {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\PHP" -Name "display_errors" -Value "Off"
}

# Prevent users from installing printer drivers
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "NoPrinterDrivers" -Value 1 -PropertyType DWord

# Restrict CD-ROM access to locally logged-on user only
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoCDBurning" -Value 1

# Microsoft network client: Digitally sign communications (always)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# Allow system to be shut down without logging on (disable)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0

# Stop and disable SNMP service
Set-Service -Name "SNMP" -StartupType Disabled
Stop-Service -Name "SNMP"

# Require secure RPC communication
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -PropertyType DWord

# IIS: Disable detailed errors
Set-WebConfigurationProperty -Filter "system.webServer/httpErrors" -Name "errorMode" -Value "DetailedLocalOnly" -PSPath "IIS:\"

# Enable Internet Explorer Enhanced Security Configuration
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Active Setup\Installed Components\{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Name "IsInstalled" -Value 1

# Deny access to this computer from the network (includes Guest)
ntrights -u Guest -r SeDenyNetworkLogonRight

# Recovery Console: Disable automatic administrative logon
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Name "SecurityLevel" -Value 1

# Microsoft network server: Digitally sign communications (always)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# Do not allow anonymous enumeration of SAM accounts and shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

# Stop and disable SNMP Trap service
Set-Service -Name "SNMPTRAP" -StartupType Disabled
Stop-Service -Name "SNMPTRAP"

# Stop and disable Net.Tcp Port Sharing Service
Set-Service -Name "NetTcpPortSharing" -StartupType Disabled
Stop-Service -Name "NetTcpPortSharing"

# Disable SMB 1.x
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

# Do not allow supported Plug and Play device redirection
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -Value 1

# Enable Internet Properties: Enhanced Protected Mode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "EnableEnhancedProtectedMode" -Value 1
