response=$(curl -X POST http://localhost:3000/api/auth/login \
-H "Content-Type: application/json" \
-d '{"email":"john@example.com","password":"Password123"}')
token=$(echo $response | jq -r '.token')
user=$(echo $response | jq -r '.user')
userId=$(echo $user | jq -r '._id')

curl -X GET "http://localhost:3000/api/profile/$userId" \
-H "Authorization: Bearer ${token}" \
-H "Content-Type: application/json"
curl -X PUT http://localhost:3000/api/auth/privacy \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d '{
            "profileVisibility": "public",
            "showEmail": false,
            "showPhone": false,
            "showAddress": true
        }'
curl -X PUT http://localhost:3000/api/auth/profile \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d '{
            "profile": {
                "firstName": "John",
                "lastName": "Doe",
                "displayName": "Johnny",
                "bio": "Full-stack developer passionate about web technologies",
                "dateOfBirth": "1990-01-15",
                "gender": "male",
                "phoneNumber": "+1-555-0123"
        },
            "address": {
                "street": "123 Main St",
                "city": "San Francisco",
                "state": "CA",
                "zipCode": "94105",
                "country": "USA"
        },
            "socialLinks": {
                "website": "https://johndoe.dev",
                "linkedin": "https://linkedin.com/in/johndoe",
                "github": "johndoe"
        },
            "professional": {
                "jobTitle": "Senior Full-Stack Developer",
                "company": "Tech Corp",
                "industry": "Technology",
                "experience": "6-10-years",
                "skills": ["JavaScript", "React", "Node.js", "MongoDB", "Python"]
        }
}'
