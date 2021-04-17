const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;
const validatePassword = require('../lib/passwordUtils').validatePassword;

// The strings represent what we will see in req.body
const customFields = {
    usernameField: 'uname',
    passwordField: 'pw'
};

// This is our "own implementation" of password verification
const verifyCallback = (username, password, done) => {
    User.findOne({ username: username }).then((user) => {

        // the null represents the error parameter.
        // User not found doesn't necessarily cause an error, so set to null.
        if (!user) {
            return done(null, false);
        }

        const isValid = validatePassword(password, user.hash, user.salt);

        if (isValid) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    });
};
const strategy = new LocalStrategy(customFields, verifyCallback);

passport.use(strategy);

// This has to do with the Express Session
// The userID will be stored in the Session (as a browser cookie)
passport.serializeUser((user, done) => {
    done(null, user.id);
});
// This one is used when we are trying to grab the User from the session
passport.deserializeUser((userId, done) => {
    User.findById(userId)
        .then((user) => {
            done(null, user);
        })
        .catch(err => done(err))
});