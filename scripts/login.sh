token=$(curl -X POST http://localhost:3000/api/auth/login \
-H "Content-Type: application/json" \
-d '{"email":"john@example.com","password":"Password123"}' \
| jq -r '.token')

update_env_var() {
    local var_name="$1"
    local new_value="$2"
    local env_file="${3:-.env}"

    if grep -q "^${var_name}=" "$env_file"; then
        # Variable exists, replace the line
        sed -i "s/^${var_name}=.*/${var_name}=${new_value}/" "$env_file"
        echo "Updated $var_name in $env_file"
    else
        # Variable doesn't exist, append it
        echo "${var_name}=${new_value}" >> "$env_file"
        echo "Added $var_name to $env_file"
    fi
}

update_env_var "TOKEN" "$token"


