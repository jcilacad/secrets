require('dotenv').config()
const express = require("express")
const ejs = require("ejs")
const app = express()
const mongoose = require("mongoose")
const { MongoClient } = require('mongodb');
const session = require('express-session')
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy
const FacebookStrategy = require("passport-facebook").Strategy
const supergoose = require('supergoose')

const url = process.env.MONGO_URL;
const PORT = process.env.PORT || 3000;

const connectionParams={
    useNewUrlParser: true
}

mongoose.set("strictQuery", false)
mongoose.connect(url,connectionParams)
    .then( () => {
        console.log('Connected to the database ')
    })
    .catch( (err) => {
        console.error(`Error connecting to the database. ${err}`);
    })


app.set("view engine", "ejs")
app.use(express.static("public"));
app.use(express.urlencoded({
    extended: true
}))

app.use(session({
    secret: 'Secret Key',
    resave: false,
    saveUninitialized: false,
}))

app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: [{secret: String}]
});

const listOfSecrets = new mongoose.Schema({
    id: String,
    secret: String
})

userSchema.plugin(supergoose);
userSchema.plugin(passportLocalMongoose);


const User = mongoose.model("User", userSchema);

const Secret = mongoose.model("Secret", listOfSecrets);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, {id: user.id, username: user.username, name: user.displayName});
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({googleId: profile.id}, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
        clientID: process.env.APP_ID,
        clientSecret: process.env.APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({facebookId: profile.id}, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home")
})

app.get("/register", function (req, res) {
    res.render("register")
})

app.get("/login", function (req, res) {
    res.render("login")
})

app.get("/secrets", function (req, res) {

    Secret.find({}, function (err, founditems) {
        if (!err) {
            res.render("secrets", {datas: founditems})
        } else {
            res.send(err)
        }

    })

})

app.get("/logout", function (req, res) {
    res.redirect("/secrets")
})

app.get("/submit", function (req, res) {

    if (req.isAuthenticated()) {
        res.render("submit")
    } else {
        res.redirect("/login")
    }

})

app.get("/auth/google",
    passport.authenticate('google', {scope: ['profile']})
);

app.get('/auth/google/secrets',
    passport.authenticate('google', {failureRedirect: '/login'}),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

app.get('/auth/facebook',
    passport.authenticate('facebook')
);

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', {failureRedirect: '/login'}),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

app.post("/logout", function (req, res, next) {
    req.logout(function (err) {
        if (!err) {
            res.redirect("/login")
        } else {
            return next(err)
        }
    })

});


app.post("/register", function (req, res) {

    const newUser = new User({
        username: req.body.username
    })

    User.register(newUser, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    })
})

app.post('/login',
    passport.authenticate('local', {failureRedirect: '/login'}),
    function (req, res) {
        res.redirect('/secrets');
    });

app.post("/submit", function (req, res) {

    const submittedSecret = {secret: req.body.secret};

    const oneSecret = req.body.secret;

    const newSecret = new Secret({
        id: req.user.id,
        secret: oneSecret
    })

    newSecret.save()

    User.updateOne(
        {_id: req.user.id},
        {$push: {secrets: submittedSecret}},
        function (err) {
            if (!err) {
                res.redirect("/secrets")
            } else {
                res.send(err)
            }
        }
    );


})


app.listen(PORT, function () {
    console.log(`Listening on port ${PORT}`)
})