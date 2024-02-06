require('./utils');

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;


const database = include('databaseConnection');
const db_utils = include('database/db_utils');
const db_users = include('database/users');
const success = db_utils.printMySQLVersion();

const port = process.env.PORT || 3000;

const app = express();

const expireTime = 1 * 60 * 60 * 1000; 


/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.use('/public', express.static('public'));

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));

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
  
    const images = ['AT_GC.gif', 'pixel.gif', 'ok.gif'];
    const randomIndex = Math.floor(Math.random() * images.length);
    const randomImage = '/public/' + images[randomIndex];
  
    res.render('members', { authenticated: req.session.authenticated, username: req.session.username, randomImage });
  });

app.get('/createTables', async (req,res) => {

    const create_tables = include('database/create_tables');

    var success = create_tables.createTables();
    if (success) {
        res.render("successMessage", {message: "Created tables."} );
    }
    else {
        res.render("errorMessage", {error: "Failed to create tables."} );
    }
});

app.get('/signup', (req, res) => {
    const errorMsg = req.query.error;
    res.render('signup', { errorMsg });
  });

app.post('/signupSubmit', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

    let errorMsg = "";
    if (!username) {
      errorMsg += "Please provide a username. ";
    }
    if (!password) {
      errorMsg += "Please provide a password. ";
    }
  
    if (errorMsg !== "") {
      res.redirect(`/signup?error=${encodeURIComponent(errorMsg)}`);
      return;
    }

    var hashedPassword = bcrypt.hashSync(password, saltRounds);

    var success = await db_users.createUser({ user: username, hashedPassword: hashedPassword });

    if (success) {
        var results = await db_users.getUsers();

        res.redirect("/members");
    }
});

app.get('/login', (req, res) => {
    const loginMsg = req.query.error;
    res.render('login', { loginMsg });
  });

app.post('/loginSubmit', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    let loginMsg = "";

    const results = await db_users.getUser({ user: username });

    if (!username || results.length !== 1) {
        loginMsg = "User not found. ";
        res.redirect(`/login?error=${encodeURIComponent(loginMsg)}`);
        return;
    }

    if (!password) {
        loginMsg = "Incorrect password. Please try again. ";
        res.redirect(`/login?error=${encodeURIComponent(loginMsg)}`);
        return;
    }

    const storedPassword = results[0].password;
    if (bcrypt.compareSync(password, storedPassword)) {
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        loginMsg = "Incorrect password. Please try again. ";
        res.redirect(`/login?error=${encodeURIComponent(loginMsg)}`);
        return;
    }
});

  
function isValidSession(req) {
	if (req.session.authenticated) {
		return true;
	}
	return false;
}

function sessionValidation(req, res, next) {
	if (!isValidSession(req)) {
		req.session.destroy();
		res.redirect('/login');
		return;
	}
	else {
		next();
	}
}

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
  });

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
