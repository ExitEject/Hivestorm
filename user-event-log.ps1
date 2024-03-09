# Define Event ID categories
$categories = @(
    @{IDs = @(4624); Name = "Account Success Logins"; Color = "Green"},
    @{IDs = @(4625); Name = "Account Failed Logins"; Color = "Red"},
    @{IDs = @(4720, 4722, 4740); Name = "Account Created/Enabled/Disabled/Locked"; Color = "Yellow"},
    @{IDs = @(4723, 4728, 4732, 4634, 4647); Name = "Account Changes"; Color = "Cyan"}
)

# Aggregate all event IDs into a single array
$allEventIDs = $categories | ForEach-Object { $_.IDs } | Select-Object -Unique

# Fetch events with specified IDs from the Security log
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = $allEventIDs
} -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending

# Limit to the most recent 100 events
$events = $events | Select-Object -First 100

# Process and format the output
foreach ($category in $categories) {
    $filteredEvents = $events | Where-Object { $category.IDs -contains $_.Id }
    if ($filteredEvents) {
        Write-Host "`n$category.Name" -ForegroundColor $category.Color
        $filteredEvents | Format-Table TimeCreated, Id, Message -AutoSize
    }
}
