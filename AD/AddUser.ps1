# Import the Active Directory module
Import-Module ActiveDirectory

# Define user details
$username = "olive"
$displayName = "olive"
$organizationalUnit = "CN=Users,DC=crewmate,DC=local"  # Adjusted to the CN path
$password = ConvertTo-SecureString "S3cur3P@ssw0rd!" -AsPlainText -Force

# Check if the user already exists
$userExists = Get-ADUser -Filter {SamAccountName -eq $username} -ErrorAction SilentlyContinue

if ($userExists) {
    Write-Output "User account '$username' already exists!"
    
    # Ensure the account is enabled
    if (-not $userExists.Enabled) {
        Enable-ADAccount -Identity $username
        Write-Output "User account '$username' has been enabled."
    }

    # Add the user to Remote Desktop Users group
    Add-ADGroupMember -Identity "Remote Desktop Users" -Members $username
    Write-Output "User account '$username' has been added to the Remote Desktop Users group."
} else {
    # Create the new user in Active Directory
    New-ADUser `
        -Name $username `
        -SamAccountName $username `
        -DisplayName $displayName `
        -Path $organizationalUnit `
        -AccountPassword $password `
        -Enabled $true `
        -PasswordNeverExpires $false `
        -ChangePasswordAtLogon $true `
        -GivenName "Olive" `
        -Surname "Crew"

    Write-Output "User account '$username' has been successfully created and enabled!"

    # Add the user to Remote Desktop Users group
    Add-ADGroupMember -Identity "Remote Desktop Users" -Members $username
    Write-Output "User account '$username' has been added to the Remote Desktop Users group."
}
