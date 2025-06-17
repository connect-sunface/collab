const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String }, // <-- removed unique
  phone: { 
    type: String, 
    unique: false, // <-- removed unique
    sparse: true
  },
  email: { 
    type: String, 
    unique: false, // <-- removed unique
    sparse: true 
  },
  password: { type: String },
  method: { 
    type: String, 
    enum: ['google', 'otp', 'password'], 
    default: 'password' 
  },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);rts = mongoose.model('User', userSchema);
