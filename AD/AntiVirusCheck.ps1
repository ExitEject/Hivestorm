# Function to list all installed products from the registry
function Get-AllInstalledProducts {
    $installedProducts = @()
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    Write-Output "Checking registry for installed products..."
    foreach ($path in $registryPaths) {
        try {
            $products = Get-ItemProperty $path
            foreach ($product in $products) {
                if ($product.DisplayName -and $product.UninstallString) {
                    Write-Output "Found product: $($product.DisplayName)"
                    Write-Output "Uninstall string: $($product.UninstallString)"
                    $installedProducts += $product | Select-Object DisplayName, UninstallString
                }
            }
        } catch {
            Write-Output "Unable to access registry path: $path"
        }
    }

    return $installedProducts
}

# Main script logic
Write-Output "Starting Program Check Script..."

$allProducts = Get-AllInstalledProducts

if ($allProducts.Count -gt 0) {
    foreach ($product in $allProducts) {
        Write-Output "Product: $($product.DisplayName)"
        Write-Output "Uninstall String: $($product.UninstallString)"
    }
} else {
    Write-Output "No valid products found in the registry."
}

Write-Output "Script execution completed."
