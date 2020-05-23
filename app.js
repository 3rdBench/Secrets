//jshint esversion:6

// Setup environment Variables
require('dotenv').config();

// Setup back-end modules
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// Setup Passport.js & related modules
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Setup Google OAuth 2.0 Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// Setup Facebook OAuth Strategy
const FacebookStrategy = require('passport-facebook').Strategy;

// Setup Mongoose findOrCreate() method
const findOrCreate = require('mongoose-findorcreate');

// Setup Express
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

// Configure session options
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

// Initialize passport & manage a session
app.use(passport.initialize());
app.use(passport.session());

// Address Mongoose deprecation warnings
mongoose.set('useNewUrlParser', true);
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
mongoose.set('useUnifiedTopology', true);

// Setup MongoDB database name
let databaseName = "userDB";

// Connect to MongoDB database for local development
// mongoose.connect("mongodb://localhost:27017/" + databaseName);

// Connect to MongoDB Atlas database for deployment in Heroku
mongoose.connect(
  "mongodb+srv://" + process.env.MONGODB_USER_ACCT + ":" + process.env.MONGODB_USER_PSWD +"@cluster0-fxsru.mongodb.net/"  + databaseName
);

// Schema for user account
// NOTE: 'username' field prevents the implicit creation of username_1 index in MongoDB Atlas which triggers
//        an Internal Server Error (HTTP Status 500) when authenticating using Facebook
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
  username: { type: String, index:false}
});

// Setup schema .plugin() to use passport-local-mongoose in salting & hashing user password
userSchema.plugin(passportLocalMongoose);

// Setup schema .plugin() to use findOrCreate() method for Facebook & Google OAuth 2.0 Strategies
userSchema.plugin(findOrCreate);

// Model for user account
const User = new mongoose.model("User", userSchema);

// Setup passport-local to create a local login strategy
passport.use(User.createStrategy());

// Serialize user account
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

// Deserialize user account
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Setup passport for Google OAuth 2.0 Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://whispering-brushlands-13731.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Setup passport for Facebook OAuth 2.0 Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://whispering-brushlands-13731.herokuapp.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


// === GET Routes ===

// Route to Home page
app.get("/", function(req, res){
  res.render("home");
});

// Route to Google login page
app.get("/auth/google", passport.authenticate('google', {scope: ["profile"]}));

// Get route to locally authenticate user after successful Google OAuth authentication
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets page
    res.redirect("/secrets");
  });

// Route to Facebook login page
app.get("/auth/facebook", passport.authenticate('facebook'));

// Locally authenticate user after successfully authenticated by Facebook's OAuth authentication
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: "/login" }),
  function(req, res) {
    // Redirect to Secrets page
    res.redirect("/secrets");
});


// Route to Login page
app.get("/login", function(req, res){
  res.render("login");
});

// Route to Registration page
app.get("/register", function(req, res){
  res.render("register");
});

// Route to Secrets page
app.get("/secrets", function(req, res){
  // Check database for users with secret field
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

// Route to Submit authenticated user's secret
app.get("/submit", function(req, res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }

});

// Route to Logout authenticated user from web app
app.get("/logout", function(req,res){
  req.logout();
  res.redirect("/");
});



// === POST Routes ===

// Route to Register a new account using email
app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err){
      console.log(err);
      res.redirect("/register");
    } else {
      // Create & save user account, setup a logged in session & redirect to secrets page
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

// Route to the Login page
app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  // Establish a login session
  req.login(user, function(err){
    if (err){
      console.log(err);
    } else {
      // Authenticate user account & redirect to secrets page
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

// Route to save authenticated user's secret for storage
app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;
  console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        // Save secret message to database
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});


// Set TCP port the app will listen to
let tcpPort = process.env.PORT;

if (tcpPort == null || tcpPort == ""){
  tcpPort = 3000;
}

app.listen(tcpPort, function() {
  console.log("Server started successfully on port: " + tcpPort);
});
