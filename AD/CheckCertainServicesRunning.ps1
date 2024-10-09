Get-Service | 
    Where-Object { $_.Name -like '*RDP*' -or $_.Name -like '*DNS*' -or $_.Name -like '*ActiveDirectory*' } |
    Select Name, DisplayName, Status | 
    Sort Status -Descending | 
    Format-Table -Property * -AutoSize | 
    Out-String -Width 4096
