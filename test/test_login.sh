RESPONSE=$(curl -X POST http://localhost:3000/api/auth/login \
           -H "Content-Type: application/json" \
           -d '{"email":"john@example.com","password":"Password123"}' \
           | jq -r '.token')


curl -X GET http://localhost:3000/api/protected \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $RESPONSE"
