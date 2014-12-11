var express = require('express');
var session = require("express-session");
var bodyParser = require('body-parser');
var app = express();
var bcrypt = require("bcrypt");

var db = require('./models');

app.set('view engine','ejs');

app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({extended:false}));
app.use(session({
    secret: 'thisIsAnOptionalButRecommendedValue',
    resave: false,
    saveUninitialized: true
}));


app.use(function(req, res, next) {
    req.getUser = function() {
        return req.session.user || false;
    }
    next();
})

app.get('/',function(req,res){
    var user = req.getUser();
    res.render('index',{user:user});
});

app.get('/restricted',function(req,res){
    if (req.getUser()) {
        res.render('restricted');
    } else {
        res.send('DENIED!')
    }
});

//login form
app.get('/auth/login',function(req,res){
    res.render('login');
});

app.post('/auth/login',function(req,res){
    //do login here (check password and set session value)
    db.user.find({where:{email:req.body.email}}).then(function(userObj) {
        if (userObj) {
            // check password now
            // res.send("we will test password now.")
            bcrypt.compare(req.body.password, userObj.password, function(err, match) {
                if (match) {
                    // store userObj in session here.
                    // res.send("password is correct!");
                    req.session.user = {
                        id: userObj.id,
                        email: userObj.email,
                        name: userObj.name
                    };
                    res.redirect("/");
                } else {
                    res.send("invalid password!");
                }
            })
        } else {
            // error - user not found.
            res.send("Unknown user.");
        }
    });
    //user is logged in forward them to the home page
    // res.redirect('/');
});

//sign up form
app.get('/auth/signup',function(req,res){
    res.render('signup');
});

app.post('/auth/signup',function(req,res){
    //do sign up here (add user to database)
    db.user.findOrCreate(
    {
        where: {
            email:req.body.email
        }, 
        defaults: {
            email:req.body.email, 
            password:req.body.password, 
            name:req.body.name
        }
    }).spread(function(user, created) {
        if (!created) {
            res.send('Email already exists in database')
        } else {
            res.send(user)
            //user is signed up forward them to the home page
            // res.redirect('/');
        }
    }).catch(function(error) {
        res.send(error);
    })
    
});

//logout
//sign up form
app.get('/auth/logout',function(req,res){
    // res.send('logged out');
    delete req.session.user;
    res.redirect('/');
});

app.listen(3000);