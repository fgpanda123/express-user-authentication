const sumTest = require('./sum');
const test = require("node:test");

test('adds 1 + 2 to equal 3', () => {
    expect(sumTest(1, 2)).toBe(3);
});
test('adds 2 + 2 to equal 3', () => {
    expect(sumTest(2, 2)).toBe(3);
})
