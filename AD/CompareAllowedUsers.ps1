$current_users = @"
Administrator
pink
brown
cyan
yellow
green
coral
black
white
blue
orange
tan
purple
red
lime
POLUS$
MIRA$
"@ -split "`n"

$allowed_users = @"
cyan
red
white
pink
blue
green
brown
purple
orange
lime
yellow
black
"@ -split "`n"

# Find unauthorized users
$unauthorized_users = $current_users | Where-Object { $_ -notin $allowed_users }

# Print unauthorized users
Write-Host "Unauthorized users:"
$unauthorized_users
