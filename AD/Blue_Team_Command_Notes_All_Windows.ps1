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

# Get capacity in GB for all logical disks
$cap = Get-CimInstance -ClassName Win32_LogicalDisk | select @{L="Capacity";E={"{0:N2}" -f ($_.Size / 1GB)}}
echo "Capacity (GB):"
$cap

#Get patch information
#You can google the KB5031358 patch version if you want to get specific information on it
get-hotfix|
select-object HotFixID,InstalledOn|
Sort-Object  -Descending -property InstalledOn|
format-table -autosize

#if an update has failed, find out why

$Failures = gwmi -Class Win32_ReliabilityRecords;
$Failures | ? message -match 'failure'  | Select -ExpandProperty message 

