current_users="Administrator
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
MIRA$"

allowed_users="cyan
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
black"

# Convert to arrays
IFS=$'\n' read -r -d '' -a current_users_array <<< "$current_users"
IFS=$'\n' read -r -d '' -a allowed_users_array <<< "$allowed_users"

# Find unauthorized users
echo "Unauthorized users:"
for user in "${current_users_array[@]}"; do
    if [[ ! " ${allowed_users_array[*]} " =~ " ${user} " ]]; then
        echo "$user"
    fi
done
