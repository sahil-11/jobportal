const { timeStamp } = require("console");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
    firstName : {
        type : String ,
        trim : true,
        required : [true , 'first name is required'],
        maxlength : '32'
    } ,
    lastName : {
        type : String ,
        trim : true,
        required : [true , 'last name is required'],
        maxlength : '32'
    },
    email : {
        type : String ,
        trim : true,
        required : [true , 'e-mail name is required'],
        unique : true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    password : {
        type : String ,
        trim : true,
        required : [true , 'last name is required'],
        minlength : [6 , 'password must have atleast 6 characters']
    },
    role : {
        type : Number ,
        default : 0
    }
    
}, {timeStamp : true})

userSchema.pre('save', async function(next){
    if(!this.isModified('password')){
        next();
    }
    this.password = await bcrypt.hash(this.password , 10);
})


// compare user's password


userSchema.methods.comparePassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password)
}


// returning a jwttoken
userSchema.methods.getJwtToken = function(){
    return jwt.sign({id:this.id},process.env.JWT_SECRET,{
        expiresIn : 3600
    })
}

    

module.exports = mongoose.model("User" , userSchema );