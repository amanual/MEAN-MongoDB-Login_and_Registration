const express = require('express');
const path = require('path');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
var session = require('express-session');
var bcrypt = require('bcrypt-as-promised');
mongoose.Promise = global.Promise;
app.use(bodyParser.urlencoded({extended: true})); 
app.use(session({secret: 'SectetKey'}));

//creating schema
mongoose.connect('mongodb://localhost/login_registration');
var UserSchema = new mongoose.Schema({    
    first_name: {
            type: String,
            required: [true, "first name is required"],
            minlength:[2, "Input at least 2 characters"]
        },
    last_name: {
        type: String,
        required: [true, "last name is required"],
        minlength: [2, "Input at least 2 characters"]
    },
    email: {
        type: String,
        lowercase: true,
        required: [true, "Email is required"],
        unique: true
    },    
    password: {
         type: String,
         required: [true, " Password is required"],
         minlength: [8, " Password must be at least 8 characters"],
         maxlength: [32, "Password must be below 32 characters"],
         validate: {
             validator: function(value){
                 return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{8,32}/.test(value);
             },
             message: "Password failed validation, you must have at least 1 number, uppercase and special character"
            },       
         },    
    birthdate: {
        type: Date,        
        required: [true, "birthday field is required"],
        validate: { 
            validator: function(value) {                
                var currentYr = new Date().getFullYear();
                var userYr = new Date(value).getFullYear();               
                var result = currentYr - userYr ;                
                if (result <= 10){                
                }   
            },
            message: "You have to be at least 10 years old"
        }
    },     
}, { timestamps: true })

UserSchema.pre('save', function(next){
    let self = this;
    bcrypt.hash(self.password, 14, function(err, hashed_password){
        if (err){
            next(err)
        }
        self.password = hashed_password
        next()
}) 
})
UserSchema.methods.validatePw = function(password){
    let user = this;    
    return bcrypt.compare(password, user.password);
}
var User = mongoose.model('User', UserSchema);
app.set('views', path.join(__dirname, './client/views'));
app.set('view engine', 'ejs');

//root route
app.get('/', function(req, res){
    res.render('index',{err: req.session.err});
})
app.post('/create', function (req, res) {   
    if (req.body.password !== req.body.password_conf) {
        let errors = {};
        errors.wrong_pwd = {
            message: "Password and confirmation password must be the same."
        };
        req.session.err = errors;
        return res.redirect('/')
    }
    var user = new User({
        first_name: req.body.first_name,
        last_name: req.body.last_name,
        email: req.body.email,
        password: req.body.password,
        birthdate: req.body.birthdate
    });
    user.save(function (err) {        
        if (err) {
            
            req.session.err = user.errors;            
            console.log("Something went wrong with creating a user");
            res.redirect('/');
        }   
        else {           
            console.log("Successfully added a user!");
            res.redirect("/")
        }
    })
})
app.post('/login', function(req, res){
    User.findOne({email: req.body.email}, function (err, users) {
        
        if (err) {            
           return  console.log("Something wrong with finding user!");
        }
        if (users === null){            
            let errors = {};
            errors.wrong_pwd = {message: "email not found!"};
            req.session.err = errors;
            console.log("User email not found!")
            return res.redirect('/')
        }else{
            console.log("validate password: ", users.validatePw(req.body.password))            
            users.validatePw(req.body.password).then(function(){
                 return res.render('main');
            }).catch(function(){
                let errors = {};
                    errors.wrong_pwd = {
                        message: "wrong password"
                    };
                    req.session.err = errors;
                    console.log("Wrong Password!")
                    return res.redirect('/')
            });            
        }
        
    })
})
app.listen(8000, function () {
    console.log("listening on port 8000");
});
