// Create a new router
const express = require("express")
const router = express.Router()
const bcrypt = require('bcrypt')
const { check, validationResult } = require('express-validator');

const redirectLogin = (req, res, next) => {
    if (!req.session.userId ) {
      res.redirect('./login') // redirect to the login page
    } else { 
        next (); // move to the next middleware function
    } 
}


router.get('/register', function (req, res, next) {
    res.render('register.ejs')
})

router.post("/registered", 
    [
        check('email').isEmail(),
        check('username').isLength({ min: 5, max: 20 }),
        check('password').isLength({ min: 8, max: 20 }),    

    ],
    function (req, res, next) {

        req.body.firstname = req.sanitize(req.body.firstname);
        req.body.lastname  = req.sanitize(req.body.lastname);
        req.body.username  = req.sanitize(req.body.username);
        req.body.email     = req.sanitize(req.body.email);

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            res.render('./register');
        }
        else {

            const saltRounds = 10;
            const plainPassword = req.body.password;

            // Hash the password
            bcrypt.hash(plainPassword, saltRounds, function (err, hashedPassword) {

                if (err) {
                    next(err);
                } else {

                    // Save the user data once hashing is done
                    let sqlquery = "INSERT INTO users (username, firstname, lastname, email, hashedPassword) VALUES (?,?,?,?,?)";
                    let newrecord = [
                        req.body.username,
                        req.body.firstname,
                        req.body.lastname,
                        req.body.email,
                        hashedPassword
                    ];

                    db.query(sqlquery, newrecord, (err, result) => {
                        if (err) {
                            next(err);
                        } else {
                            result = 'Hello ' + req.body.firstname + ' ' + req.body.lastname + ' you are now registered!  We will send an email to you at ' + req.body.email;
                            result += ' Your password is: ' + req.body.password + ' and your hashed password is: ' + hashedPassword;
                            res.send(result);
                        }
                    });
                }
            });
        }
    }
);


router.get('/list', redirectLogin , function (req, res, next) {
    let sqlquery = 'SELECT username FROM users';
    db.query(sqlquery, (err, result) => {
            if (err) {
                next(err)
            } else {
            res.render("userlist.ejs", {users:result})
            }
         });
});

router.post('/loggedin', function (req, res, next) {

    let sqlquery = "SELECT hashedPassword FROM users WHERE username = ?";

    db.query(sqlquery, [req.body.username], (err, result) => {
        if (err) {
            next(err);
        } 
        else if (result.length === 0) {

            // 🔹 Log failed attempt
            db.query("INSERT INTO login_audit (username, success) VALUES (?,?)",
                     [req.body.username, 0]);

            res.send('User not found!');
        } 
        else {

            let hashedPassword = result[0].hashedPassword;

            bcrypt.compare(req.body.password, hashedPassword, function(err, match) {
                if (err) {

                    // 🔹 Log failed attempt
                    db.query("INSERT INTO login_audit (username, success) VALUES (?,?)",
                             [req.body.username, 0]);

                    res.send('Login unsuccessful!');
                } 
                else if (match == true) {

                    // 🔹 Log successful login
                    db.query("INSERT INTO login_audit (username, success) VALUES (?,?)",
                             [req.body.username, 1]);

                    res.send('Login successful!');
                    // Save user session here, when login is successful
                    req.session.userId = req.body.username;

                } 
                else {

                    // 🔹 Log failed attempt
                    db.query("INSERT INTO login_audit (username, success) VALUES (?,?)",
                             [req.body.username, 0]);

                    res.send('Incorrect password!');
                }
            });
        }
    });
});

router.get('/audit', function (req, res, next) {
    let sqlquery = "SELECT * FROM login_audit ORDER BY time DESC";

    db.query(sqlquery, (err, result) => {
        if (err) {
            next(err);
        } else {
            res.render('audit.ejs', { audit: result });
        }
    });
});




// Export the router object so index.js can access it
module.exports = router
