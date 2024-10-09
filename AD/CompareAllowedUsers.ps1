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


# Function to remove unauthorized admin privileges and verify removal with logging
function Remove-UnauthorizedAdminPrivileges {
    param (
        [string[]]$unauthorized_admins
    )
    
    foreach ($admin in $unauthorized_admins) {
        try {
            Write-Host "Attempting to remove admin privileges from account: $admin" -ForegroundColor Yellow
            
            # Remove the user from the Administrators group
            Remove-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction Stop
            
            # Verification: Check if the user is still in the Administrators group
            $isMember = Get-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction SilentlyContinue
            
            if ($isMember) {
                Write-Host "Failed to remove admin privileges from: $admin" -ForegroundColor Red
            } else {
                Write-Host "Successfully removed admin privileges from: $admin" -ForegroundColor Green
            }
        }
        catch {
            Write-Host ("Error removing admin privileges from $admin " + $($_)) -ForegroundColor Red
        }
    }
}




# Function to check if a user is in the Administrators group
function Is-UserAdmin {
    param (
        [string]$username
    )
    
    try {
        $member = Get-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction SilentlyContinue
        return $null -ne $member
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

# Ask the user if they want to remove admin privileges
if ($unauthorized_admins.Count -gt 0) {
    $response = Read-Host "`nDo you want to remove admin privileges from unauthorized accounts? (yes/no)"
    if ($response.Trim().ToLower() -eq 'yes') {
        if ($unauthorized_admins.Count -gt 0) {
            # Remove admin privileges from unauthorized admins
            Remove-UnauthorizedAdminPrivileges -unauthorized_admins $unauthorized_admins
        } else {
            Write-Host "No unauthorized admins to remove." -ForegroundColor Yellow
        }
    } else {
        Write-Host "No accounts will be modified." -ForegroundColor Yellow
    }
} else {
    Write-Host "No unauthorized users or admins found." -ForegroundColor Green
}
