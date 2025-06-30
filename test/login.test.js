const request = require('supertest');
const jwt = require('jsonwebtoken');
const {describe, it} = require("node:test");
const app = require('../app').app;
let token;
const login_information = {"email":"john@example.com","password":"Password123"}
const expectedKeys = ["__v", "_id","professional", "privacy", "name", "email", "isActive", "isEmailVerified", "isPhoneVerified", "createdAt", "updatedAt", "lastLogin"]

describe('POST /api/auth/login', async () => {
    it("should respond with 200 and json file containing profile information", async () => {
        return request(app)
            .post('/api/auth/login')
            .send(login_information)
            .set('Accept', 'application/json')
            .expect('Content-Type', 'application/json; charset=utf-8')
            .expect(200)
            .then(async (res) => {
                expect(Object.keys(res.body.user).sort()).toEqual(expectedKeys.sort())
                token = res.body.token;
            })


    })
})
