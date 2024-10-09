current_users= """
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
"""
allowed_users= """
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
"""
current_users_set = set(user.strip() for user in current_users.strip().splitlines())
allowed_users_set = set(user.strip() for user in allowed_users.strip().splitlines())
unauthorized_users = current_users_set - allowed_users_set

print("Unauthorized users:")
for user in unauthorized_users:
    print(user)
