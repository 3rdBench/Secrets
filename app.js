//jshint esversion:6

// Environment Variables
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// Passport.js & related modules
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Google OAuth 2.0 Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// Facebook OAuth Strategy
const FacebookStrategy = require('passport-facebook');

// Mongoose findOrCreate() method
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

// Setup & configure session options
app.use(session({
  secret: "Our little secret.",
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

// Connect to local MongoDB database
mongoose.connect("mongodb://localhost:27017/userDB");

// Schema for user account
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
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
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Setup passport for Facebook OAuth 2.0 Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Get route to render the home page
app.get("/", function(req, res){
  res.render("home");
});

// Get route to render Google's login page
app.get("/auth/google", passport.authenticate('google', {scope: ["profile"]}));

// Get route to locally authenticate user after successful Google OAuth authentication
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets page
    res.redirect("/secrets");
  });

// Get route to render Facebook's login page
app.get("/auth/facebook", passport.authenticate('facebook'));

// Get route to locally authenticate user after successful Facebook OAuth authentication
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets page
    res.redirect("/secrets");
});


// Get route to render the login page
app.get("/login", function(req, res){
  res.render("login");
});

// Get route to render the registration page
app.get("/register", function(req, res){
  res.render("register");
});

// Get route to render the secrets page
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

// Get route to render the submit page
app.get("/submit", function(req, res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }

});

// Get route to terminate active login session & cookie then redirect back to home page
app.get("/logout", function(req,res){
  req.logout();
  res.redirect("/");
});


// Post route to register a new account
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

// Post route to login a user
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

// Post route to save the submitted secret
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

app.listen(3000, function(){
  console.log("Server started on port 3000.");
});
