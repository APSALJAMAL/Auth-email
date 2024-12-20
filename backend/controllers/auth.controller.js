import User from '../models/user.model.js';
import bcryptjs from 'bcryptjs';
import { errorHandler } from '../utils/error.js';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { sendOtpEmail,sendResendOtpEmail,sendResetPasswordEmail,sendLoginEmail,sendSignupEmail,sendOtpRegisterEmail,sendResendOtpRegisterEmail } from '../utils/emailService.js';
import { checkUserBlocked } from './user.controller.js';
import TempUser from '../models/tempuser.model.js';
import geoip from 'geoip-lite'; // Use for detecting location from IP address


// Initial signup and OTP generation
export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  try {
    if (!username || !email || !password) {
      return next(errorHandler(400, 'All fields are required'));
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return next(errorHandler(400, 'Invalid email format'));
    }

    // Validate password strength
    if (password.length < 8) {
      return next(errorHandler(400, 'Password must be at least 8 characters long'));
    }

    // Check if email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(errorHandler(400, 'Email is already registered'));
    }

    // Hash the password
    const hashedPassword = bcryptjs.hashSync(password, 10);

    // Generate OTP and set expiration
    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = Date.now() + 2 * 60 * 1000; // 2 minutes validity

    // Save temporary user data
    const tempUser = new TempUser({
      username,
      email,
      password: hashedPassword,
      otp: generatedOtp,
      otpExpires,
    });

    await tempUser.save();

    // Send OTP to email
    await sendOtpRegisterEmail(email, generatedOtp);

    return res.status(200).json({
      message: 'Signup successful. Please check your email for the OTP.',
    });
  } catch (error) {
    next(error);
  }
};


export const signupvalidateOtp = async (req, res) => {
  const { otp } = req.body;
  const { email } = req.params; // Get email from params

  try {
    // Find the temporary user by email
    const user = await TempUser.findOne({ email });

    // If the user is not found, return an error
    if (!user) {
      return res.status(400).json({ message: 'No temporary account found with this email.' });
    }

    // Check if OTP and OTP expiration time exist
    if (!user.otp || !user.otpExpires) {
      return res.status(400).json({ message: 'OTP or OTP expiration time is missing.' });
    }

    // Validate OTP expiration
    const now = new Date();
    if (user.otpExpires < now) {
      return res.status(400).json({ message: 'OTP has expired.' });
    }

    // Validate OTP against the stored OTP
    if (user.otp !== otp.trim()) {
      return res.status(400).json({ message: 'Invalid OTP.' });
    }

    // OTP validated successfully, clear the OTP and OTP expiration using $unset
    await TempUser.updateOne(
      { email },
      { $unset: { otp: '', otpExpires: '' } }
    );

    // Create a new user after OTP validation
    const newUser = new User({
      username: user.username,
      email: user.email,
      password: user.password,
    });

    await newUser.save();
    await TempUser.deleteOne({ email });

    await sendSignupEmail(email);

    // Send success response
    return res.status(200).json({ message: 'Account created successfully. Please sign in.' });

  } catch (error) {
    console.error('Error validating OTP:', error);
    return res.status(500).json({ message: 'Error validating OTP' });
  }
};



// Resend OTP
export const signupresendOtp = async (req, res, next) => {
  const { email } = req.body;

  try {
    const user = await TempUser.findOne({ email });
    if (!user) {
      return next(errorHandler(400, 'No temporary account found with this email.'));
    }

    // Generate a new OTP and expiration time
    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = Date.now() + 2 * 60 * 1000; // 2 minutes validity

    // Update the OTP in the database
    user.otp = generatedOtp;
    user.otpExpires = otpExpires;
    await user.save();

    // Send new OTP to the user's email
    await sendResendOtpRegisterEmail(user.email, generatedOtp);

    res.status(200).json({
      message: 'OTP has been resent to your email.',
    });
  } catch (error) {
    next(error);
  }
};

export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  // Validate request body
  if (!email || !password || email === '' || password === '') {
    return next(errorHandler(400, 'All fields are required'));
  }

  try {
    const validUser = await User.findOne({ email });
    
    if (!validUser) {
      return next(errorHandler(404, 'User not found'));
    }

    // Check if the user is blocked
    const isBlocked = await checkUserBlocked(email);
    if (isBlocked) {
      return next(errorHandler(403, 'You are blocked by the admin'));
    }

    // Validate password
    const validPassword = bcryptjs.compareSync(password, validUser.password);
    if (!validPassword) {
      return next(errorHandler(400, 'Invalid password'));
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: validUser._id, isAdmin: validUser.isAdmin },
      process.env.JWT_SECRET
    );

    // Exclude password from the response
    const { password: pass, ...rest } = validUser._doc;

    // Set the token in cookies and return the user data
    res
      .status(200)
      .cookie('access_token', token, {
        httpOnly: true,
      })
      .json(rest);

    // Send login notification email
    try {
      const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress; // Get user's IP
      const locationData = geoip.lookup(ip); // Get location from IP
      const location = locationData
        ? `${locationData.city}, ${locationData.country}`
        : 'an unknown location';

      await sendLoginEmail(email, validUser.username, location);
    } catch (emailError) {
      console.error('Failed to send login email:', emailError);
    }

  } catch (error) {
    next(error);
  }
};


export const google = async (req, res, next) => {
  const { email, name, googlePhotoUrl } = req.body;

  try {
    // Check if the user exists
    const user = await User.findOne({ email });

    if (user) {
      // Check if the user is blocked
      if (user.isBlocked) {
        return res.status(403).json({ success: false, message: 'You are blocked by the admin' });
      }

      // User exists and is not blocked, generate token
      const token = jwt.sign(
        { id: user._id, isAdmin: user.isAdmin },
        process.env.JWT_SECRET,
        { expiresIn: '5d' } // Token expires in 5 days
      );
      const { password, ...rest } = user._doc;

      res
        .status(200)
        .cookie('access_token', token, {
          httpOnly: true,
        })
        .json({ success: true, ...rest });

    } else {
      // Create new user if they do not exist
      const generatedPassword =
        Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);
      const hashedPassword = bcryptjs.hashSync(generatedPassword, 10);

      const newUser = new User({
        username: name.toLowerCase().split(' ').join('') + Math.random().toString(9).slice(-4),
        email,
        password: hashedPassword,
        profilePicture: googlePhotoUrl,
      });

      await newUser.save();

      // Generate token for new user
      const token = jwt.sign(
        { id: newUser._id, isAdmin: newUser.isAdmin },
        process.env.JWT_SECRET,
        { expiresIn: '5d' } // Token expires in 5 days
      );
      const { password, ...rest } = newUser._doc;

      res
        .status(200)
        .cookie('access_token', token, {
          httpOnly: true,
        })
        .json({ success: true, ...rest });
    }

  } catch (error) {
    next(error);
  }
};




export const validateOtp = async (req, res) => {
  const { otp } = req.body;

  try {
    const user = await User.findOne({ otp });
    if (!user) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Clear the OTP after validation
    user.otp = undefined;
    await user.save();

    res.status(200).json({ message: 'OTP validated successfully. You can now reset your password.' });
  } catch (error) {
    res.status(500).json({ message: 'Error validating OTP' });
  }
};

// Send reset password link
export const forgotPassword = async (req, res) => {
  const { email } = req.body; // Accept email instead of userId
  try {
    const user = await User.findOne({ email }); // Find user by email
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a six-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a six-digit OTP
    user.otp = otp;
    user.otpExpires = Date.now() + 2 * 60 * 1000; // OTP expires in 2 minutes

    await user.save();

    // Send OTP via email (you'll implement email logic here)
    await sendOtpEmail(user.email, otp);

    res.json({ message: 'OTP sent to email' });
  } catch (error) {
    console.error('Error in forgotPassword:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Resend OTP Controller
export const resendOtp = async (req, res) => {
  const { email } = req.body; // Include the email in the request body

  try {
    const user = await User.findOne({ email }); // Find user by email
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a new OTP and save it as a string
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Ensure it's a six-digit string
    user.otp = otp;
    user.otpExpires = Date.now() + 2 * 60 * 1000; // Set a new expiration time for the OTP (2 minutes)
    await user.save();

    console.log('Generated OTP:', otp); // Log the generated OTP for debugging

    // Send new OTP via email
    await sendResendOtpEmail(user.email, otp);

    res.status(200).json({ message: 'New OTP sent to your email' });
  } catch (error) {
    console.error('Error in resendOtp:', error); // Log the error for debugging
    res.status(500).json({ message: 'Error resending OTP' });
  }
};

export const resetPassword = async (req, res) => {
  const { email } = req.params; // Get email from the URL parameters
  const { password } = req.body; // Get new password from request body

  try {
    // Validate the input
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Hash the password
    const hashedPassword = await bcryptjs.hash(password, 10);
    
    // Update the user's password
    user.password = hashedPassword;
    await user.save();

    await sendResetPasswordEmail(user.email);

    // Send success response
    res.status(200).json({ message: "Password has been reset successfully!" });
  } catch (error) {
    console.error("Server error while resetting password:", error); // Log the error
    res.status(500).json({ message: "Server error while resetting password." });
  }
};

export const getOldPassword = async (req, res) => {
  const { email } = req.body;

  try {
    // Validate the input
    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    res.json({ oldPasswordHash: user.password });
  } catch (error) {
    console.error("Error fetching old password:", error); // Log the error for debugging
    res.status(500).json({ message: "Server error." });
  }
};


