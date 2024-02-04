require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3020;

const app = express();

const Joi = require("joi");

app.use('/public', express.static('public'));

app.set('view engine', 'ejs');

app.use(express.static(__dirname + "/public"));

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const { database } = require('./databaseConnection');


const userCollection = database.db(mongodb_database).collection('users');

const { MongoClient, ObjectId } = require('mongodb');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
});

app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}
));

// function isValidSession(req) {
//   if (req.session.authenticated) {
//     return true;
//   }
//   return false;
// }

// function sessionValidation(req, res, next) {
//   if (isValidSession(req)) {
//     next();
//   }
//   else {
//     res.redirect('/login');
//   }
// }

app.get('/', (req, res) => {
  const authenticated = req.session.authenticated;
  const username = req.session.username;

  res.render('index', { authenticated, username });
});

app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }

  const images = ['atSad.gif', 'atVibe.gif', 'atSoupMe.gif'];
  const randomIndex = Math.floor(Math.random() * images.length);
  const randomImage = '/public/' + images[randomIndex];

  res.render('members', { authenticated: req.session.authenticated, username: req.session.username, randomImage });
});


app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/signup', (req, res) => {
  const errorMsg = req.query.error;
  res.render('signup', { errorMsg });
});

app.post('/signupSubmit', async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  // Check for empty fields
  let errorMsg = "";
  if (!username) {
    errorMsg += "Please provide a username. ";
  }
  if (!email) {
    errorMsg += "Please provide an email. ";
  }
  if (!password) {
    errorMsg += "Please provide a password. ";
  }

  // If any field is missing, redirect back to /signup with error message
  if (errorMsg !== "") {
    res.redirect(`/signup?error=${encodeURIComponent(errorMsg)}`);
    return;
  }

  // Validate inputs using Joi
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required()
  });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect(`/signup?error=${encodeURIComponent("Invalid input. Please check your details.")}`);
    return;
  }

  // Check if username already exists
  const existingUser = await userCollection.findOne({ username: { $eq: username } });
  if (existingUser) {
    const errorMsg = "Username already exists.";
    res.redirect(`/signup?error=${encodeURIComponent(errorMsg)}`);
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  // Add user to MongoDB database using parameterized query
  await userCollection.insertOne({
    username,
    email,
    password: hashedPassword,
    user_type: "user", // Assigning a default user_type of "user"
  });

  console.log("Inserted user");

  // Set session variables
  req.session.authenticated = true;
  req.session.username = username;
  req.session.email = email;
  req.session.user_type = "user";

  res.redirect("/members");
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/loginSubmit', async (req, res) => {
  // extract email and password from request body
  const { email, password } = req.body;

  // validate email using Joi
  const emailSchema = Joi.string().email().required();
  const emailValidationResult = emailSchema.validate(email);
  if (emailValidationResult.error != null) {
    console.log(emailValidationResult.error);
    res.redirect('/login');
    return;
  }

  // find user in database using email
  const user = await userCollection.findOne({ email });
  if (!user) {
    console.log('invalid email/password combination');
    const errorMsg = 'Invalid email/password combination.';
    res.render('loginSubmit', { errorMsg: errorMsg });
    return;
  }

  // compare password with stored BCrypted password
  const isPasswordMatch = await bcrypt.compare(password, user.password);
  if (!isPasswordMatch) {
    console.log('password is incorrect');
    const errorMsg = 'Password is incorrect.';
    res.render('loginSubmit', { errorMsg: errorMsg });
    return;
  }

  // store username in session
  req.session.authenticated = true;
  req.session.username = user.username;
  req.session.cookie.maxAge = expireTime;
  req.session.user_type = user.user_type;

  // redirect to members page
  res.redirect('/members');
});

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
