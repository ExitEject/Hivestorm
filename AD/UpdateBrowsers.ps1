# Function to download and install Google Chrome
function Update-Chrome {
    Write-Host "Updating Google Chrome..." -ForegroundColor Green
    $chromeInstallerUrl = "https://dl.google.com/chrome/install/standalonesetup64.exe"
    $chromeInstallerPath = "$env:TEMP\chrome_installer.exe"

    Invoke-WebRequest -Uri $chromeInstallerUrl -OutFile $chromeInstallerPath
    Start-Process -FilePath $chromeInstallerPath -ArgumentList "/silent", "/install" -Wait
    Remove-Item $chromeInstallerPath

    Write-Host "Google Chrome has been updated!" -ForegroundColor Green
}

# Function to download and install Microsoft Edge
function Update-Edge {
    Write-Host "Updating Microsoft Edge..." -ForegroundColor Green
    $edgeInstallerUrl = "https://msedgesetup.azureedge.net/Stable/MicrosoftEdgeSetup.exe"
    $edgeInstallerPath = "$env:TEMP\edge_installer.exe"

    Invoke-WebRequest -Uri $edgeInstallerUrl -OutFile $edgeInstallerPath
    Start-Process -FilePath $edgeInstallerPath -ArgumentList "/silent", "/install" -Wait
    Remove-Item $edgeInstallerPath

    Write-Host "Microsoft Edge has been updated!" -ForegroundColor Green
}

# Function to download and install Mozilla Firefox
function Update-Firefox {
    Write-Host "Updating Mozilla Firefox..." -ForegroundColor Green
    $firefoxInstallerUrl = "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US"
    $firefoxInstallerPath = "$env:TEMP\firefox_installer.exe"

    Invoke-WebRequest -Uri $firefoxInstallerUrl -OutFile $firefoxInstallerPath
    Start-Process -FilePath $firefoxInstallerPath -ArgumentList "-ms" -Wait
    Remove-Item $firefoxInstallerPath

    Write-Host "Mozilla Firefox has been updated!" -ForegroundColor Green
}

# Update browsers, uncomment/comment as needed
Write-Host "Check the code comment/uncomment as needed. If the updates aren't working, uninstall the old one, then pull the new one."
Write-Host "You may also need to check the registry and group policies"
Update-Chrome
#Update-Edge
#Update-Firefox
