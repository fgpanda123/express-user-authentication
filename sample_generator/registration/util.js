// Sample Data Generator for User Registration

class UserSampleGenerator {
    constructor() {
        this.firstNames = [
            'John', 'Jane', 'Michael', 'Sarah', 'David', 'Emily', 'Robert', 'Jessica',
            'William', 'Ashley', 'James', 'Amanda', 'Christopher', 'Melissa', 'Daniel',
            'Michelle', 'Matthew', 'Kimberly', 'Anthony', 'Amy', 'Mark', 'Angela',
            'Donald', 'Helen', 'Steven', 'Deborah', 'Paul', 'Rachel', 'Joshua', 'Carolyn'
        ];

        this.lastNames = [
            'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller',
            'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez',
            'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin',
            'Lee', 'Perez', 'Thompson', 'White', 'Harris', 'Sanchez', 'Clark',
            'Ramirez', 'Lewis', 'Robinson'
        ];

        this.domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'protonmail.com', 'company.com', 'university.edu',
            'tech.io', 'startup.co', 'business.net'
        ];
    }

    // Generate a random name (2-50 characters)
    generateName() {
        const firstName = this.getRandomElement(this.firstNames);
        const lastName = this.getRandomElement(this.lastNames);
        return `${firstName} ${lastName}`;
    }

    // Generate a valid email
    generateEmail() {
        const firstName = this.getRandomElement(this.firstNames).toLowerCase();
        const lastName = this.getRandomElement(this.lastNames).toLowerCase();
        const domain = this.getRandomElement(this.domains);

        // Various email formats
        const formats = [
            `${firstName}.${lastName}@${domain}`,
            `${firstName}${lastName}@${domain}`,
            `${firstName}_${lastName}@${domain}`,
            `${firstName}${this.getRandomNumber(10, 999)}@${domain}`,
            `${firstName.charAt(0)}${lastName}@${domain}`
        ];

        return this.getRandomElement(formats);
    }

    // Generate a password (minimum 8 characters)
    generatePassword() {
        function containsUppercase(str) {
            return /[A-Z]/.test(str);
        }
        function containsLowerCase(str) {
            return /[a-z]/.test(str);
        }

        function containsNumeric(str) {
            return /[0-9]/.test(str);
        }

        function containsSpecial(str) {
            return /[!@#$%^&*]/.test(str);
        }
        const length = this.getRandomNumber(8, 16);
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        const special = '!@#$%^&*'
        const numbers = '0123456789'
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        let password = '';

        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        switch (password) {
            case !containsUppercase(password):
                password[Math.floor(Math.random() * password.length)] = uppercase.charAt(Math.floor(Math.random() * uppercase.length));
            case !containsNumeric(password):
                password[Math.floor(Math.random() * password.length)] = numbers.charAt(Math.floor(Math.random() * numbers.length));
            case !containsLowerCase(password):
                password[Math.floor(Math.random() * password.length)] = lowercase.charAt(Math.floor(Math.random() * lowercase.length));
            case !containsSpecial(password):
                password[Math.floor(Math.random() * password.length)] = special.charAt(Math.floor(Math.random() * special.length));

        }

        return password;
    }

    // Generate a single user sample
    generateUser() {
        return {
            name: this.generateName(),
            email: this.generateEmail(),
            password: this.generatePassword()
        };
    }

    // Generate multiple user samples
    generateUsers(count = 10) {
        const users = [];
        const usedEmails = new Set(); // Ensure unique emails

        while (users.length < count) {
            const user = this.generateUser();

            // Ensure email uniqueness
            if (!usedEmails.has(user.email)) {
                usedEmails.add(user.email);
                users.push(user);
            }
        }

        return users;
    }

    // Generate users with specific patterns for testing
    generateTestUsers() {
        return {
            valid: this.generateUsers(5),
            edgeCases: [
                {
                    name: 'Al', // Minimum length name
                    email: 'a@b.co', // Minimum valid email
                    password: '12345678' // Minimum length password
                },
                {
                    name: 'A'.repeat(50), // Maximum length name
                    email: 'very.long.email.address.for.testing@example.com',
                    password: 'VeryLongPasswordWith123!@#'
                }
            ],
            invalid: [
                {
                    name: 'X', // Too short
                    email: 'invalid-email',
                    password: '123' // Too short
                },
                {
                    name: 'A'.repeat(51), // Too long
                    email: 'no-at-symbol.com',
                    password: 'short'
                }
            ]
        };
    }

    // Utility methods
    getRandomElement(array) {
        return array[Math.floor(Math.random() * array.length)];
    }

    getRandomNumber(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }
}

// Usage Examples
const generator = new UserSampleGenerator();

// Generate a single user
console.log('Single User Sample:');
console.log(generator.generateUser());
console.log();

// Generate multiple users
console.log('Multiple Users Sample:');
console.log(generator.generateUsers(3));
console.log();

// Generate test data with edge cases
console.log('Test Data with Edge Cases:');
const testData = generator.generateTestUsers();
console.log('Valid users:', testData.valid);
console.log('Edge cases:', testData.edgeCases);
console.log('Invalid examples:', testData.invalid);

function generateJSONSamples(count = 10) {
    const generator = new UserSampleGenerator();
    return JSON.stringify(generator.generateUsers(count), null, 2);
}
// Export for use in other files

module.exports.UserSampleGenerator = UserSampleGenerator;
module.exports.generateJSONSamples = generateJSONSamples;
