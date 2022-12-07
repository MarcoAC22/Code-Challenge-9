// Requiring Modules
const express = require("express");
var expressLayouts = require("express-ejs-layouts");
const app = express();
const mongoose = require("mongoose");

const passport = require("passport");
const session = require("express-session");
const UserDetails = require("./User");
const routes = require("./router");
const crypto = require("crypto");
require("dotenv").config();
const AuthRouter = require('./auth')

// set up view engine and layout
app.use(expressLayouts);
app.use('/', AuthRouter('/.env'));
app.set("layout", "./pages/layout/main");
app.set("view engine", "ejs");

// Set up session
app.use(
  session({
    secret: crypto.randomBytes(20).toString("hex"),
    resave: false,
    saveUninitialized: true,
  })
);

app.use(express.urlencoded({ extended: false }));

// Set up passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(UserDetails.createStrategy());
passport.serializeUser(UserDetails.serializeUser());
passport.deserializeUser(UserDetails.deserializeUser());

app.use(routes);

const PORT = process.env.PORT || 8080;

// Set up express server
const server = app.listen(PORT, () => {
  // Connecting Mongoose
  mongoose
    .connect(process.env.DATABASE_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => {
      console.log("Connected to database");
      console.log(`Listening on port ${PORT}`);
    });
});

