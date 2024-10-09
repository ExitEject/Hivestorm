# Blue Team Command Notes
#FQDN
([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname

# Get just domain name
(Get-WmiObject -Class win32_computersystem).domain

#OS and Pwsh info
$Bit = (get-wmiobject Win32_OperatingSystem).OSArchitecture ; 
$V = $host | select-object -property "Version" ; 
$Build = (Get-WmiObject -class Win32_OperatingSystem).Caption ; 
write-host "$env:computername is a $Bit $Build with Pwsh $V"

#Get Hardware, BIOS, and Disk Space info

Write-Host "Hardware, BIOS, and Disk Space info"

#Get BIOS Info
gcim -ClassName Win32_BIOS | fl Manufacturer, Name, SerialNumber, Version;
#Get processor info
gcim -ClassName Win32_Processor | fl caption, Name, SocketDesignation;
#Computer Model
gcim -ClassName Win32_ComputerSystem | fl Manufacturer, Systemfamily, Model, SystemType
#Disk space in Gigs, as who wants bytes?
gcim  -ClassName Win32_LogicalDisk |
Select -Property DeviceID, DriveType, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}} | fl

## Let's calculate an individual directory, C:\Sysmon, and compare with disk memory stats
# Calculate the size of all files in the Users directory
#replace C:\Users with any directory you want to check or add a -Recurse flag to continue digging.
$size = (gci c:\Users | Where-Object { -not $_.PSIsContainer } | measure Length -s).sum / 1Gb
write-host "Sysmon Directory in Gigs: $size"

# Get free space in GB for all logical disks
$free = Get-CimInstance -ClassName Win32_LogicalDisk | select @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace / 1GB)}}
echo "Free space (GB):"
$free

Write-Host "Disk information"

# Get capacity in GB for all logical disks
$cap = Get-CimInstance -ClassName Win32_LogicalDisk | select @{L="Capacity";E={"{0:N2}" -f ($_.Size / 1GB)}}
echo "Capacity (GB):"
$cap

#Get patch information
#You can google the KB5031358 patch version if you want to get specific information on it

Write-Host "Installed hotfixes/patched:"

get-hotfix|
select-object HotFixID,InstalledOn|
Sort-Object  -Descending -property InstalledOn|
format-table -autosize

#if an update has failed, find out why

Write-Host "If an Update has failed, here's why:"

$Failures = gwmi -Class Win32_ReliabilityRecords;
$Failures | ? message -match 'failure'  | Select -ExpandProperty message 

#Only on a DC, find when all users where made, if you get
Write-Host "Checking to see when users were created and printing their information."
# Attempt to import the Active Directory module with error handling
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "Error: The 'ActiveDirectory' module could not be imported. Ensure RSAT is installed." -ForegroundColor Red
}

# Look back 30 days at user creation
$When = ((Get-Date).AddDays(-30)).Date;

# Attempt to retrieve AD user creation dates
try {
    $users = Get-ADUser -Filter {whenCreated -ge $When} -Properties whenCreated | 
             Sort-Object whenCreated -Descending
             
    # Check if any users were returned
    if ($users.Count -gt 0) {
        $users | ForEach-Object { 
            Write-Host "User: $($_.SamAccountName), Created: $($_.whenCreated)"
        }
    } else {
        Write-Host "No users were created in the last 30 days." -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Error: Could not retrieve AD users. Ensure you are running this script on a domain controller and have the necessary permissions." -ForegroundColor Red
}


#Print logged in users
Write-Host "Users logged in:"
qwinsta
Start-Sleep -Seconds 2
Write-Host "`nIf you need to log them off type: logoff 2 /v" 
write-host "replace 2 with their assigned ID`n"

#Retrieve all hosts that are enabled
Write-Host "Here are the users currently enabled on this machine:"
Get-LocalUser | ? Enabled -eq "True"

Write-Host "`nDo you need to change a password?`n Try this: Set-ADAccountPassword -Identity `$user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "`$newPass" -Force) -verbose`nMake sure you give the variables values before doing this."
Write-Host "`nIf the user is a local one, not domain joined, you will have to try this`n`nnet user frank `"password`""