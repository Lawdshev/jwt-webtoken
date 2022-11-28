const mongoose = require("mongoose");
require('dotenv').config();
const DB_URI = process.env.DB_URI

mongoose.connect(DB_URI).then(()=> console.log('connected to mongodb'))
.catch(err=> console.error("couldn't connect",err));