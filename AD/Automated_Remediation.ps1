# Import the Active Directory module
Import-Module ActiveDirectory

# Get the domain distinguished name
$domainDN = (Get-ADDomain).DistinguishedName

# Get the "Administrators" group from the Builtin container
$adminGroup = Get-ADGroup -Filter { Name -eq "Administrators" } -SearchBase "CN=Builtin,$domainDN"

# Define current users (typically from the Administrators group)
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

# Define the AD group that controls RDP access
$rdpADGroup = "Remote Desktop Users"

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

# Define allowed admins
$allowed_admins = @"
cyan
red
white
pink
"@ -split "\r?\n" | ForEach-Object { $_.Trim() }

# Function to ensure authorized users are in Remote Desktop Users group
function Add-RDPAccess-AD {
    param (
        [string[]]$authorized_users,
        [string]$adGroup
    )

    foreach ($user in $authorized_users) {
        try {
            # Check if user is already in the RDP AD group
            $isMember = Get-ADGroupMember -Identity $adGroup -Recursive | Where-Object { $_.SamAccountName -eq $user }

            if (-not $isMember) {
                Write-Host "Adding $user to $adGroup group for RDP access" -ForegroundColor Yellow
                Add-ADGroupMember -Identity $adGroup -Members $user -ErrorAction Stop
                Write-Host "Successfully added $user to $adGroup group" -ForegroundColor Green
            } else {
                Write-Host "$user already has RDP access in $adGroup." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Failed to add $user to $adGroup group: $($_)" -ForegroundColor Red
        }
    }
}

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
