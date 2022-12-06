const express = require('express');
const session = require('express-session'); 
const passport = require('passport'); 
const LocalStrategy = require('passport-local');
const crypto = require('crypto'); 

function AuthRouter(database) {
    var router = express.Router();
    router.use(session({
        secret: 'qxPgm22jswetGqbnG', 
        resave: false,
        saveUninitialized: false
    }));
    router.use(passport.authenticate('session'));
    router.use((req, res, next) => {
        if (req.user) {
            res.locals.user = req.user;
        }
        next();
    });
    passport.use(
        new LocalStrategy(
            async function verify(username, password, callback) {
                let foundUser = await database.collections.users.findOne({ username: username }).catch((error) => {
                    if (error) {
                        callback('Incorrect username or password.', null);
                    }
                });
                if (!foundUser) {
                    callback('Incorrect username or password.', null);
                    return;
                }
                crypto.pbkdf2(password, foundUser.salt, 310000, 32, 'sha256', function (_, hashedPassword) {
                    if (foundUser.password !== hashedPassword.toString('hex')) {
                        return callback('Incorrect username or password.', null);
                    }
                    return callback(null, foundUser);
                });
            }
        )
    );
    passport.serializeUser(function (user, callback) {
        return callback(null, { id: user.id, username: user.username });
    });
    passport.deserializeUser(function (user, callback) {
        return callback(null, user);
    });

    router.get('./pages/login', function (req, res) {
        res.render('./pages/login', { errorMessage: req.query.errorMessage || null });
    });

    router.get('./pages/signup', function (req, res) {
        res.render('./pages/signup', { errorMessage: req.query.errorMessage || null });
    });

    router.post('./pages/login', (req, res, next) => {
        passport.authenticate('local', async (_, user) => {
            await new Promise((resolve, reject) => {
                // If the user is registered and password is correct
                // Then create a cookie for their session
                req.login({
                    id: user._id.toString(),
                    username: user.username
                }, (_) => {resolve();});
            });
            res.redirect('/');
        })(req, res, next);
    });

    router.post('/register', async function (req, res) {
        let data = req.body;
        const salt = crypto.randomBytes(16).toString('hex');
        const hashedPassword = await new Promise((resolve, _) => {
            crypto.pbkdf2(data.password, salt, 310000, 32, 'sha256', (_, hashedPassword) => {
                resolve(hashedPassword);
            });
        });
        let user = await database.collections.users.insertOne({
            ...data,
            salt: salt,
            password: hashedPassword.toString('hex')
        });
        await new Promise((resolve, _) => {
            req.login({
                id: user.insertedId.toString(),
                username: data.username
            }, (_) => {resolve();});
        });
        res.redirect('/');
    });

    router.get('/logout', function (req, res, next) {
        req.logout(function (err) {
            if (err) { return next(err); }
            res.redirect('/');
        });
    });

    return router;
}

module.exports = AuthRouter;