const request = require('supertest');
const app = require('../app')
const test_case1 = {
      data: {"email":"john@example.com","password":"Password123"},
      expected: ["professional", "privacy", "_id", "name", "email", "isActive", "isEmailVerified", "isPhoneVerified", "createdAt", "updatedAt", "last_login"]}

describe('POST /login', () => {
    it("should respond with 200 and json file containing profile information", async () => {
        const response = await request(app)
        .post('/login')
        .send(data)
        .expect('Content-Type', /json/)
        .expect(200);
    expect(Object.keys(response.body)).toHaveProperty('user')
    expect(Object.keys(response.body.user).sort()).toEqual(expectedKeys.sort());

    })
})