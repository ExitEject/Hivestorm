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
"@ -split "`n"

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
"@ -split "`n"

# Function to disable unauthorized accounts
function Disable-UnauthorizedAccounts {
    param (
        [string[]]$unauthorized_users
    )
    
    foreach ($user in $unauthorized_users) {
        # Disable the account (uncomment the following line to actually disable)
        # Disable-LocalUser -Name $user
        Write-Host "Disabling account: $user"
    }
}

# Function to check if accounts are disabled
function Check-AccountsDisabled {
    param (
        [string[]]$unauthorized_users
    )

    foreach ($user in $unauthorized_users) {
        $account = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        if ($account -and -not $account.Enabled) {
            Write-Host "Account $user is disabled."
        } else {
            Write-Host "Account $user is not disabled or does not exist."
        }
    }
}

# Find unauthorized users
$unauthorized_users = $current_users | Where-Object { $_ -notin $allowed_users }

# Print unauthorized users
Write-Host "Unauthorized users:"
$unauthorized_users

# Ask the user if they want to disable the accounts
if ($unauthorized_users.Count -gt 0) {
    $response = Read-Host "Do you want to disable the unauthorized accounts? (yes/no)"
    if ($response -eq 'yes') {
        Disable-UnauthorizedAccounts -unauthorized_users $unauthorized_users
        # Check if the accounts are disabled
        Check-AccountsDisabled -unauthorized_users $unauthorized_users
    } else {
        Write-Host "No accounts will be disabled."
    }
} else {
    Write-Host "No unauthorized users found."
}
