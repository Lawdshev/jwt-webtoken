const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcryptjs')
require('dotenv').config();
const Joi = require('joi');
const mongoose = require("mongoose");
const { json } = require("express");
const app = express();
const DB_URI = process.env.DB_URI;
const jwtKey = process.env.JWTKEY
const jwtExpirySeconds = 300
app.use(json())


if(!jwtKey){
    console.error('FATAL ERROR: JWT-KEY UNDEFINED');
    process.exit(1)
}

mongoose.connect(DB_URI).then(()=> console.log('connected to mongodb')).then(()=>(app.listen(8080,()=> console.log('listening on port 8080'))))
.catch(err=> console.error("couldn't connect",err));

const userSchema = mongoose.Schema({
    name:{
        type: String,
        reqiured: true,
        minlength: 5,
        maxlength: 25
    },
    email: {
        type: String,
        reqiured: true,
        unique: true,
    },
    password:{
        type: String,
        reqiured: true,
        minlength: 5,
        maxlength: 255
    },
})

const User = mongoose.model('User',userSchema);

const signupSchema = Joi.object({
    name: Joi.string().min(5).max(25).required(),
    password: Joi.string().min(5).max(255).required(),
    email: Joi.string().min(5).max(225).required().email(),
})


app.post('/signup',async(req,res)=>{
   const {error} = signupSchema.validate(req.body);
    if(error){
       res.status(400).send(error.details[0].message)
       return
    }
    let user = await User.findOne({email: req.body.email});
    if(user){
        return res.status(401).send('email already in use')
    }
    user = new User({
        name: req.body.name,
        password: req.body.password,
        email:req.body.email
    })
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password,salt);
    await user.save();
    const token = jwt.sign({ email:req.body.email }, jwtKey, {
        algorithm: "HS256",
        expiresIn: jwtExpirySeconds,
    })
    res.header('x-auth-token',token).send('registration successful')
});

app.post('/auth',async(req,res)=>{
   const {error} = signupSchema.validate({name: 'xxxxxx',password:req.body.password,email:req.body.email});
    if(error){
       res.status(400).send(error.details[0].message)
       return
    }

    let user = await User.findOne({email: req.body.email});
    if(!user){
        res.status(401).send('invalid email or password')
        return 
    }

    const validPassword = await bcrypt.compare(req.body.password,user.password);
    if(!validPassword){ 
        res.status(400).send('invalid email or password')
    }else{
        const token = jwt.sign({ email:req.body.email }, jwtKey, {
            algorithm: "HS256",
            expiresIn: jwtExpirySeconds,
        })
        res.send(token)
    } 
});

