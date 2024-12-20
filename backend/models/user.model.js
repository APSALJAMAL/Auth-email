import mongoose from 'mongoose';
import bcrypt from 'bcryptjs'; // Use import instead of require

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, // Regex for email validation
    },
    password: {
      type: String,
      required: true,
    },
    profilePicture: {
      type: String,
      default:
        'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png',
    },
    role: {
      type: String,
      enum: ['user', 'admin', 'owner'], // Define allowed roles
      default: 'user',
    },
    isBlocked: {
      type: Boolean,
      default: false,
    },
    otp: {
      type: String,
    },
    otpExpires: {
      type: Date,
    },
  },
  { timestamps: true }
);

/**
 * Method to check access based on roles.
 * @param {String} role - The role to check against ("user", "admin", "owner").
 * @returns {Boolean} - Whether the user has access to the specified role.
 */
userSchema.methods.hasAccess = function (role) {
  const roleHierarchy = {
    user: 1,
    admin: 2,
    owner: 3,
  };

  return roleHierarchy[this.role] >= roleHierarchy[role];
};


const User = mongoose.model('User', userSchema);

export default User;
