## System Information
```cmd
systeminfo
hostname
ipconfig /all
wmic qfe list #displays installed updates
```

## Users and Group Information
```cmd
net user
net user $user #to get information about a specific user
net localgroup #list groups
net localgroup administrators #list users in the administrators group
```

## Network Information
```cmd
netstat -ano #active network connections
net share #shared folders
netstat -an | find "LISTENING" #only listening connections
netsh advfirewall show allprofiles #check firewall settings
```
## Process and Service information
```cmd
tasklist #list running processes
taskkill /PID [pid] /F  #kills a process on its pid
sc query #list services
sc qc $servicename #get detailed information on a service
schtasks /query /fo LIST /v #display all scheduled tasks
```

## Security and Audit Logs
```cmd
Get-WinEvent -LogName Security #get security event logs
auditpol /get /category:* #get audit policies
secedit /export /cfg C:\security_config.txt #get local security policies and export a file
```

