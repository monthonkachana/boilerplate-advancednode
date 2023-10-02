const passport = require('passport');
const bcrypt = require('bcrypt');

module.exports = function (app, myDataBase) {
    app.route('/').get((req, res) => {
        res.render('index', {
            title: 'Connected to Database',
            message: 'Please log in',
            showLogin: true,
            showRegistration: true,
            showSocialAuth: true
        });
    });

    app.route('/login').post(passport.authenticate('local', { failureRedirect: '/' }), (req, res) => {
        res.redirect('/profile');
    });

    app.route('/profile').get(ensureAuthenticated, (req, res) => {
        res.render('profile', { username: req.user.username });
    });

    app.route('/logout').get((req, res) => {
        req.logout();
        res.redirect('/');
    });
    //Registration of New Users The logic of step 1 should be as follows:
    //1. Query database with findOne
    //2. If there is an error, call next with the error
    //3. If a user is returned, redirect back to home
    //4. If a user is not found and no errors occur, then insertOne into the database with the username and password. As long as no errors occur there, call next to go to step 2, authenticating the new user, which you already wrote the logic for in your POST /login route.
    app.route('/register').post((req, res, next) => {
        //bcrypt (hashing algorithm) สำหรับการเข้ารหัสรหัสผ่านและข้อมูลอื่น ๆ เพื่อป้องกันการแยกแยะและการถอดรหัสข้อมูล ปลอดภัยในระบบ 
        const hash = bcrypt.hashSync(req.body.password, 12);
        myDataBase.findOne({ username: req.body.username }, (err, user) => {
            if (err) {
                next(err);
            } else if (user) {
                res.redirect('/');
            } else {
                myDataBase.insertOne({
                    username: req.body.username,
                    password: hash
                },
                    (err, doc) => {
                        if (err) {
                            res.redirect('/');
                        } else {
                            // The inserted document is held within
                            // the ops property of the doc
                            next(null, doc.ops[0]);
                        }
                    }
                )
            }
        })
    },
        passport.authenticate('local', { failureRedirect: '/' }),
        (req, res, next) => {
            res.redirect('/profile');
        }
    );

    app.route('/auth/github').get(passport.authenticate('github'));
    app.route('/auth/github/callback').get(passport.authenticate('github', { failureRedirect: '/' }), (req, res) => {
        req.session.user_id = req.user.id;
        res.redirect("/chat");
    })

    app.use((req, res, next) => {
        res.status(404)
            .type('text')
            .send('Not Found');
    });
}
//middleware to requests for the profile page before the argument to the GET request
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
};