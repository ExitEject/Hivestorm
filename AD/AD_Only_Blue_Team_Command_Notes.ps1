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
Write-Host "`nIf you need to log them off type:"
Write-Host "logoff 2 /v" -ForegroundColor Green 
write-host "replace 2 with their assigned ID`n"

#Retrieve all hosts that are enabled
Write-Host "Here are the users currently enabled on this machine:"
Get-LocalUser | ? Enabled -eq "True"

# Ask the user if they want to proceed with viewing PowerShell history
$Response = Read-Host "Do you want to display PowerShell history for each AD user? (y/n)"

# Check if the user's response is 'yes'
if ($Response -eq "y") {
    Write-Host "Powershell History for each AD User:"
    Write-Host

    # Get the list of PowerShell history files
    $Users = (Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt).FullName
    $Pasts = @($Users)

    # Loop through each user's history file and display its content
    foreach ($Past in $Pasts) {
        Write-Host "`n----User Pwsh History Path $Past---`n" -ForegroundColor Magenta
        Get-Content $Past
    }
} else {
    Write-Host "You chose not to display PowerShell history." -ForegroundColor Yellow
}

Get-ChildItem -Path C:\Users -Include *.txt,*.bak,*.ini,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log -File -Recurse -ErrorAction SilentlyContinue


Write-Host "Do you need to reenable something like Microsoft Defender but there's no GPO?"
Write-Host "Search run -> regedit -> HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender -> DisableAntiSpyware -> Set to 0"
Write-Host "`nDo you need to change a password?`n Try this:"
Write-Host "Set-ADAccountPassword -Identity `$user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "`$newPass" -Force) -verbose"  -ForegroundColor Green
Write-Host "`nMake sure you give the variables values before doing this."
Write-Host "`nIf the user is a local one, not domain joined, you will have to try this:"
Write-Host "`nnet user frank `"password`"`n" -ForegroundColor Green
Write-Host "Do you need to disable an account?"
Write-Host "`n #needs the SAMAccountName`n`n`$user = "lizzie"; `nDisable-ADAccount -Identity "`$user" `n`n#check its disabled`n(Get-ADUser -Identity $user).enabled`n" -ForegroundColor Green
Write-Host "If it is a Local Account you can try this:"
Write-Host "Disable-LocalUser -name "bad_account$"" -ForegroundColor Green
Write-Host "`nNeed to remove a user from a group? Try this:"
Write-Host "`$user = "erochester"`nremove-adgroupmember -identity Administrators -members `$User -verbose -confirm:`$false" -ForegroundColor Green
Write-Host "Need to check running/stopped services?"
Write-Host "get-service|Select Name,DisplayName,Status| sort status -descending | ft -Property * -AutoSize| Out-String -Width 4096" -ForegroundColor Green
Write-Host "You can also add this:" -NoNewline
Write-host " | findstr "`$servicename" " -ForegroundColor Green
Write-Host "This will filter those results by the name of the service to find quickly if it is running or not."
Write-Host "This command will get all dependent services on the service in question"
Write-Host "Get-Service -Name `$Service -DependentServices" -ForegroundColor Green
Write-Host "This command will get all running executables and the command that spawned them, might be useful for finding malware: "
Write-Host "Get-WmiObject win32_service |? State -match "running" |`nselect Name, DisplayName, PathName, User | sort Name |`nft -wrap -autosize" -ForegroundColor Green
Write-Host "Need to find CNAME aliases? nslookup -type=CNAME $CNAME"
Write-Host "nslookup -type=CNAME mira.crewmate.local"
