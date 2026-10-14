const assert = require("node:assert/strict");
const test = require("node:test");

global.location = {
    origin: "http://localhost",
    pathname: "/pages/test.html",
    search: "",
    replace() {},
    assign() {}
};
global.localStorage = {
    getItem() { return null; },
    setItem() {},
    clear() {}
};
global.document = {
    addEventListener() {},
    querySelectorAll() { return []; },
    getElementById() { return null; }
};

const { validateEmail, passwordError } = require("../js/auth.js");

test("email validation mirrors registration format checks", () => {
    assert.equal(validateEmail(" person@example.com "), true);
    assert.equal(validateEmail("invalid@localhost"), false);
    assert.equal(validateEmail("missing-at.example.com"), false);
});

test("password validation mirrors complexity and bcrypt byte limit", () => {
    assert.equal(passwordError("StrongPass123!"), "");
    assert.match(passwordError("weakpass"), /uppercase/);
    assert.match(passwordError("Abcdef1"), /8 characters/);
    assert.match(passwordError("A😀😀😀a1"), /8 characters/);
    assert.match(passwordError("Ā".repeat(36) + "Aa1"), /72 bytes/);
});