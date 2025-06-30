const request = require('supertest');
const {describe, it} = require("node:test");
const app = require('../app').app;
let token;
const test_case1 = {
      data: {"email":"john@example.com","password":"Password123"},
      expected: ["__v", "_id","professional", "privacy", "name", "email", "isActive", "isEmailVerified", "isPhoneVerified", "createdAt", "updatedAt", "lastLogin"]}

describe('POST /api/auth/login', async () => {
    it("should respond with 200 and json file containing profile information", async () => {
        return request(app)
            .post('/api/auth/login')
            .send(test_case1.data)
            .set('Accept', 'application/json')
            .expect('Content-Type', 'application/json; charset=utf-8')
            .expect(200)
            .then(async (res) => {
                expect(Object.keys(res.body.user).sort()).toEqual(test_case1.expected.sort())
                token = res.body.token;
            })


    })
})
