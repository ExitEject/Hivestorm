# Ask user for the username
$user = Read-Host "Enter the username"

# Check registry paths
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $registryPaths) {
    Write-Host "Checking $path..." -ForegroundColor Green 
    Get-ItemProperty -Path $path | ForEach-Object {
        $_.PSObject.Properties | Where-Object { $_.Value -and $_.Name -ne "PSPath" } | ForEach-Object {
            Write-Output "$($_.Name): $($_.Value)"
        }
    }
}

# Check startup folders
$startupPaths = @(
    "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $startupPaths) {
    Write-Host "Checking $path..." -ForegroundColor Green
    Get-ChildItem -Path $path | ForEach-Object {
        Write-Output $_.FullName
    }
}

# Check Automatic Services
Write-Host "Checking Automatic Services..." -ForegroundColor Green
Get-WmiObject -Class Win32_Service -Filter "StartMode = 'Auto'" | ForEach-Object {
    Write-Host -NoNewline -ForegroundColor Yellow $_.Name
    Write-Host ": $($_.PathName)"

}
