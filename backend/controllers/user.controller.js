import bcryptjs from 'bcryptjs';
import { errorHandler } from '../utils/error.js';
import User from '../models/user.model.js';
import { sendLogoutEmail } from '../utils/emailService.js';
const validateUsername = (username) => {
  if (username.length < 7 || username.length > 20) {
    throw errorHandler(400, 'Username must be between 7 and 20 characters');
  }
  if (username.includes(' ')) {
    throw errorHandler(400, 'Username cannot contain spaces');
  }
  if (username !== username.toLowerCase()) {
    throw errorHandler(400, 'Username must be lowercase');
  }
  if (!/^[a-zA-Z0-9]+$/.test(username)) {
    throw errorHandler(400, 'Username can only contain letters and numbers');
  }
};

const validatePassword = (password) => {
  if (password.length < 6) {
    throw errorHandler(400, 'Password must be at least 6 characters');
  }
  return bcryptjs.hashSync(password, 10);
};

export const updateUser = async (req, res, next) => {
  try {
    // Check if the user has the correct role
    if (req.user.role !== 'admin' && req.user.id !== req.params.userId) {
      throw errorHandler(403, 'You are not allowed to update this user');
    }

    const { password, username, email, profilePicture } = req.body;

    if (password) req.body.password = validatePassword(password);
    if (username) validateUsername(username);

    const updatedUser = await User.findByIdAndUpdate(
      req.params.userId,
      {
        $set: { username, email, profilePicture, password: req.body.password },
      },
      { new: true }
    );

    const { password: _, ...rest } = updatedUser._doc;
    res.status(200).json(rest);
  } catch (error) {
    next(error);
  }
};



export const signout = async (req, res, next) => {
  try {
    const { email, username } = req.user; // Assuming verifyToken middleware populates req.user
    res.clearCookie('access_token').status(200).json('User has been signed out');

    // Send logout email
    try {
      await sendLogoutEmail(email, username);
    } catch (emailError) {
      console.error('Failed to send logout email:', emailError);
    }
  } catch (error) {
    next(error);
  }
};



export const getUsers = async (req, res, next) => {
  try {
    // Only allow admin or owner roles
   

    const { startIndex = 0, limit = 9, sort = 'desc', startDate, endDate, search } = req.query;
    const sortDirection = sort === 'asc' ? 1 : -1;

    // Create a date filter if startDate or endDate are provided
    const dateFilter = {};
    if (startDate) dateFilter.$gte = new Date(startDate);
    if (endDate) {
      const adjustedEndDate = new Date(endDate);
      adjustedEndDate.setHours(23, 59, 59, 999);  // Adjust the end date to the end of the day
      dateFilter.$lte = adjustedEndDate;
    }

    // Build the query object for filtering
    const query = {};
    if (startDate || endDate) query.createdAt = dateFilter;
    if (search) {
      const regex = new RegExp(search, 'i');
      query.$or = [
        { username: regex },
        { email: regex },
        { role: regex },
        { isBlocked: search.toLowerCase() === 'blocked' },
      ];
    }

    // Fetch the users based on the query, sorted and limited
    const users = await User.find(query)
      .select('-password')  // Exclude the password field from the result
      .skip(Number(startIndex))
      .limit(Number(limit))
      .sort({ createdAt: sortDirection });

    // Fetch the total count of users and users created in the last month
    const totalUsers = await User.countDocuments(query);
    const lastMonthUsers = await User.countDocuments({
      createdAt: { $gte: new Date(new Date().setMonth(new Date().getMonth() - 1)) },
    });

    // Return the response
    res.status(200).json({ users, totalUsers, lastMonthUsers });
  } catch (error) {
    next(error);  // Pass the error to the error handler middleware
  }
};



export const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) throw errorHandler(404, 'User not found');

    const { password, ...rest } = user._doc;
    res.status(200).json(rest);
  } catch (error) {
    next(error);
  }
};

export const updateRole = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) throw errorHandler(404, 'User not found');

    // Validate the new role
    const validRoles = ['user', 'admin', 'owner'];
    if (!validRoles.includes(req.body.role)) {
      throw errorHandler(400, 'Invalid role');
    }

    user.role = req.body.role; // The new role to be assigned
    await user.save();

    res.status(200).json({ message: 'User role updated successfully', user });
  } catch (error) {
    next(error);
  }
};



export const blockUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) throw errorHandler(404, 'User not found');

    user.isBlocked = true; // Block the user
    await user.save();

    res.status(200).json({ message: 'User has been blocked' });
  } catch (error) {
    next(error);
  }
};


export const unblockUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) throw errorHandler(404, 'User not found');

    user.isBlocked = false; // Unblock the user
    await user.save();

    res.status(200).json({ message: 'User has been unblocked' });
  } catch (error) {
    next(error);
  }
};



export const checkUserBlocked = async (email) => {
  const user = await User.findOne({ email });
  return user ? user.isBlocked : null;
};



export const deleteUser =  async (req, res, next) => {
  try {
    // Find the user by ID and delete
    const user = await User.findByIdAndDelete(req.params.userId);

    // If the user doesn't exist, return a 404 error
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Return a success response
    res.status(200).json({ message: 'User has been deleted successfully' });
  } catch (error) {
    // Handle any other errors
    next(error);
  }
};