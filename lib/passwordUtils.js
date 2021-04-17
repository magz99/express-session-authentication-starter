const crypto = require('crypto');

// Passport.js doesn't really provide a way to do these out-of-the-box
// so they are defined below by us
function validatePassword(password, hash, salt) {
    const hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

    return hash === hashVerify;
}

// See PKCS #5: Password-Based Cryptography Specification
function genPassword(password) {
    const salt = crypto.randomBytes(32).toString('hex');
    const genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

    return {
        salt: salt,
        hash: genHash
    };
}

module.exports.validatePassword = validatePassword;
module.exports.genPassword = genPassword;