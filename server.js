const express = require('express');
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const mongodbSession = require('connect-mongodb-session')(session);

// File imports
const userModel = require('./modules/userModel');
const { userDataValidation, isEmailValidate } = require('./utils/authUtils');
const isAuth = require('./middlewares/isAuthMiddlewares');

// Constants
const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const store = new mongodbSession({
    uri: MONGO_URI,
    collection: 'sessions'
});



//middlewares
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SECRET_KEY,
    store: store,
    resave: false,
    saveUninitialized: false,
}))

//db connection
mongoose.connect(MONGO_URI)
    .then(() => console.log("DB connected successfully"))
    .catch((err) => console.log(err));


app.get('/', (req, res) => {
    return res.send('server is up and running')
});
// Registration
app.get('/register', (req, res) => {
    return res.render('registerPage')
});
app.post('/register', async (req, res) => {
    console.log(req.body);
    const { name, email, username, password } = req.body

    //data validation
    try {
        await userDataValidation({ name, email, username, password })

    } catch (error) {
        return res.status(400).json(error);
    }

    try {
        const userEmailExist = await userModel.findOne({ email: email });

        console.log(userEmailExist);
        //check if exixs
        if (userEmailExist) {
            return res.status(400).json('Email.already exit.')
        }

        const userNameExist = await userModel.findOne({ username });

        if (userNameExist) {
            return res.status(400).json('user Name already exit.')
        }

        // hash the password
        const hashedPassword = await bcrypt.hash(password,
            Number(process.env.SALT)
        )

        const userObj = new userModel({
            //schema : client
            name: name,
            email: email,
            username: username,
            password: hashedPassword,
        });
        const userDb = await userObj.save();

        return res.redirect('/login')
    } catch (error) {
        return res.send(500).json({ messege: " Internal server error", error: error })
    }
});

app.get('/login', (req, res) => {
    console.log("Rendering login page");  // Added logging
    return res.render('loginPage');
});

app.post('/login', async (req, res) => {
    console.log(req.body);

    const { loginId, password } = req.body;
    // Data validation
    if (!loginId || !password) return res.status(400).json("Missing user loginId/Password");

    if (typeof loginId !== "string")
        return res.status(400).json("LoginId is not a text");

    if (typeof password !== "string")
        return res.status(400).json("Password is not a text");

    try {
        let userDb = {};
        // Find the user based on loginId
        if (isEmailValidate({ key: loginId })) {
            userDb = await userModel.findOne({ email: loginId }).select("+password");
        } else {
            userDb = await userModel.findOne({ username: loginId }).select("+password");
        }

        if (!userDb) {
            return res.status(400).json("User not found, please register first");
        }
        // Compare the password
        const isMatch = await bcrypt.compare(password, userDb.password);
        if (!isMatch) {
            return res.status(400).json("Incorrect Password");
        }

        // Storing session in DB
        req.session.isAuth = true;
        req.session.user = {
            userId: userDb._id,
            username: userDb.username,
            email: userDb.email,
        };

        return res.redirect('/dashboard');
    } catch (error) {  // Corrected Typo
        console.error("Error during login:", error);  // Added logging
        return res.status(500).json({ messege: "Internal server error", error: error });
    }
});

// Error Logging Added in Registration
app.post('/register', async (req, res) => {
    console.log(req.body);
    const { name, email, username, password } = req.body;

    // Data validation
    try {
        await userDataValidation({ name, email, username, password });
    } catch (error) {
        return res.status(400).json(error);
    }

    try {
        const userEmailExist = await userModel.findOne({ email: email });
        console.log(userEmailExist);

        if (userEmailExist) {
            return res.status(400).json('Email already exists.');
        }

        const userNameExist = await userModel.findOne({ username });

        if (userNameExist) {
            return res.status(400).json('Username already exists.');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, Number(process.env.SALT));

        const userObj = new userModel({
            // Schema : client
            name: name,
            email: email,
            username: username,
            password: hashedPassword,
        });
        const userDb = await userObj.save();

        return res.redirect('/login');
    } catch (error) {
        console.error("Error during registration:", error);  // Added logging
        return res.status(500).json({ messege: "Internal server error", error: error });
    }
});

//Dashboard
app.get('/dashboard', isAuth, (req, res) => {
    return res.render("dashboardpage");
})
//logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json(err);
        } else {
            return res.status(200).json("Logout successful")
        }
    })

});


app.post('/logout-out-from-all', isAuth, async (req, res) => {
    console.log(req.session);
    const username = req.session.user.username;

    const sessionSchema = new mongoose.Schema({ _id: String }, { strict: false });
    const sessionModel = mongoose.model('session', sessionSchema);

    try {
        const deleteDb = await sessionModel.deleteMany({
            "session.user.username": username,
        });

        console.log(deleteDb);

        return res.status(200).json(`Logout from ${deleteDb.deletedCount} all devices successful`);
    } catch (error) {
        return res.status(500).json(error);
    }

    
});

//Todo's API
app.post("/create-item"), isAuth, (req, res) => {
    console.log(req.body);
    return res.send("all ok");
}

app.listen(PORT, () => {
    console.log('server is running at:')
    console.log(`http://localhost:${PORT}`)
});