// models/TempUser.js
import mongoose from 'mongoose';

const tempUserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true, // Allows duplicates since `unique` is not specified
  },
  password: {
    type: String,
    required: true,
  },
  otp: {
    type: String,
    required: true,
  },
  otpExpires: {
    type: Date,
    required: true,
  },
});

const TempUser = mongoose.model('TempUser', tempUserSchema);

export default TempUser;
