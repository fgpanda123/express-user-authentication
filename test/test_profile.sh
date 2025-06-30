curl -X PUT http://localhost:3000/api/auth/profile \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYxY2ZiNTQ5YTRhZTAzYmE5ZDk4ZjIiLCJpYXQiOjE3NTEyNDU0ODIsImV4cCI6MTc1MTMzMTg4Mn0.rpVCWmYTr8nrJQ9KsQrSC9hRMnwEgJrmTydnih9jKuI" \
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