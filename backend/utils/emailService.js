import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables from .env file

// Create a transporter object using SMTP transport
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,       // Use the SMTP_HOST from .env
  port: process.env.SMTP_PORT,       // Use the SMTP_PORT from .env
  secure: process.env.SMTP_PORT === '465', // Set to true if using port 465
  auth: {
    user: process.env.SMTP_MAIL,     // Your email
    pass: process.env.SMTP_PASSWORD,  // Your email password or App Password
  },
});

// Function to send an email with HTML template
export const sendEmail = async (to, subject, text, html) => {
  const mailOptions = {
    from: process.env.SMTP_MAIL,
    to,
    subject,
    text,   // Plain text version
    html,   // HTML content version
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.response);
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Failed to send email. Please try again later.');
  }
};

// OTP Email Template
const otpEmailRegisterTemplate = (otp) => `
  <div style="font-family: Arial, sans-serif; line-height: 1.5;">
    <h2>Your OTP for Register</h2>
    <p>Use the following One-Time Password (OTP) to Register:</p>
    <h3 style="background-color: #f0f0f0; padding: 10px; display: inline-block;">${otp}</h3>
    <p>Please use this OTP within the next 2 minutes.</p>
    <p>If you did not request this, please ignore this email.</p>
  </div>
`;

// Resend OTP Email Template
const resendOtpEmailRegisterTemplate = (otp) => `
  <div style="font-family: Arial, sans-serif; line-height: 1.5;">
    <h2>Your New OTP for Register</h2>
    <p>You have requested a new One-Time Password (OTP) to Register:</p>
    <h3 style="background-color: #f0f0f0; padding: 10px; display: inline-block;">${otp}</h3>
    <p>Please use this OTP within the next 2 minutes.</p>
    <p>If you did not request this, please ignore this email.</p>
  </div>
`;

// OTP Email Template
const otpEmailTemplate = (otp) => `
  <div style="font-family: Arial, sans-serif; line-height: 1.5;">
    <h2>Your OTP for Password Reset</h2>
    <p>Use the following One-Time Password (OTP) to reset your password:</p>
    <h3 style="background-color: #f0f0f0; padding: 10px; display: inline-block;">${otp}</h3>
    <p>Please use this OTP within the next 2 minutes.</p>
    <p>If you did not request this, please ignore this email.</p>
  </div>
`;

// Resend OTP Email Template
const resendOtpEmailTemplate = (otp) => `
  <div style="font-family: Arial, sans-serif; line-height: 1.5;">
    <h2>Your New OTP for Password Reset</h2>
    <p>You have requested a new One-Time Password (OTP) to reset your password:</p>
    <h3 style="background-color: #f0f0f0; padding: 10px; display: inline-block;">${otp}</h3>
    <p>Please use this OTP within the next 2 minutes.</p>
    <p>If you did not request this, please ignore this email.</p>
  </div>
`;

// Password Reset Confirmation Email Template
const passwordResetConfirmationTemplate = () => `
  <div style="font-family: Arial, sans-serif; line-height: 1.5;">
    <h2>Password Reset Confirmation</h2>
    <p>Your password has been successfully reset. If you did not request this change, please contact our support team immediately.</p>
    <p>If this was you, no further action is needed. You can now log in with your new password.</p>
  </div>
`;

// Signup Confirmation Email Template
const signupConfirmationTemplate = (username) => `
  <div style="font-family: Arial, sans-serif; line-height: 1.5;">
    <h2>Welcome to Our Platform, ${username}!</h2>
    <p>Thank you for signing up! We’re excited to have you on board.</p>
    <p>If you have any questions, feel free to reach out to our support team.</p>
    <p>Best Regards,</p>
    <p>The Jamal's Team</p>
  </div>
`;

// Login Notification Email Template
const loginNotificationTemplate = (username, location) => `
  <div style="font-family: Arial, sans-serif; line-height: 1.5;">
    <h2>New Login Detected</h2>
    <p>Hello ${username},</p>
    <p>We noticed a new login to your account from ${location}. If this was you, no action is needed.</p>
    <p>If this wasn’t you, please reset your password immediately to secure your account.</p>
    <p>Best Regards,</p>
    <p>The Jamal's Team</p>
  </div>
`;

// Logout Confirmation Email Template
const logoutConfirmationTemplate = (username) => `
  <div style="font-family: Arial, sans-serif; line-height: 1.5;">
    <h2>Logout Confirmation</h2>
    <p>Hello ${username},</p>
    <p>You have successfully logged out of your account. If this wasn’t you, please reset your password immediately.</p>
    <p>Best Regards,</p>
    <p>The Jamal's Team</p>
  </div>
`;

// Function to send OTP email
export const sendOtpRegisterEmail = async (to, otp) => {
  const subject = 'Your OTP for Register';
  const text = `Your OTP for Register is: ${otp}. Please use it within the next 2 minutes.`;
  const html = otpEmailRegisterTemplate(otp); // Use the OTP HTML template
  await sendEmail(to, subject, text, html);
};

// Function to send Resend OTP email
export const sendResendOtpRegisterEmail = async (to, otp) => {
  const subject = 'Your New OTP for Register';
  const text = `Your new OTP for Register is: ${otp}. Please use it within the next 2 minutes.`;
  const html = resendOtpEmailRegisterTemplate(otp); // Use the Resend OTP HTML template
  await sendEmail(to, subject, text, html);
};

// Function to send OTP email
export const sendOtpEmail = async (to, otp) => {
  const subject = 'Your OTP for Password Reset';
  const text = `Your OTP for password reset is: ${otp}. Please use it within the next 2 minutes.`;
  const html = otpEmailTemplate(otp); // Use the OTP HTML template
  await sendEmail(to, subject, text, html);
};

// Function to send Resend OTP email
export const sendResendOtpEmail = async (to, otp) => {
  const subject = 'Your New OTP for Password Reset';
  const text = `Your new OTP for password reset is: ${otp}. Please use it within the next 2 minutes.`;
  const html = resendOtpEmailTemplate(otp); // Use the Resend OTP HTML template
  await sendEmail(to, subject, text, html);
};

// Function to send Password Reset Confirmation email
export const sendResetPasswordEmail = async (to) => {
  const subject = 'Password Reset Confirmation';
  const text = 'Your password has been reset successfully. If you did not request this change, please contact support immediately.';
  const html = passwordResetConfirmationTemplate(); // Use the Password Reset Confirmation HTML template
  await sendEmail(to, subject, text, html);
};

// Function to send Logout Confirmation Email
export const sendLogoutEmail = async (to, username) => {
  const subject = 'Logout Confirmation';
  const text = `Hello ${username}, you have successfully logged out of your account. If this wasn’t you, please reset your password immediately.`;
  const html = logoutConfirmationTemplate(username); // Use the Logout Confirmation HTML template
  await sendEmail(to, subject, text, html);
};


// Function to send Login Notification Email
export const sendLoginEmail = async (to, username, location) => {
  const subject = 'New Login Notification';
  const text = `Hello ${username}, we noticed a new login to your account from ${location}. If this wasn’t you, please reset your password immediately.`;
  const html = loginNotificationTemplate(username, location); // Use the Login Notification HTML template
  await sendEmail(to, subject, text, html);
};


// Function to send Signup Confirmation Email
export const sendSignupEmail = async (to, username) => {
  const subject = 'Welcome to Our Platform!';
  const text = `Welcome to our platform, ${username}! Thank you for signing up.`;
  const html = signupConfirmationTemplate(username); // Use the Signup Confirmation HTML template
  await sendEmail(to, subject, text, html);
};


