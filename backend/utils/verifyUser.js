import jwt from 'jsonwebtoken';
import User from '../models/user.model.js'; // Adjust the path to your User model

export const verifyToken = async (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json('Token not found. Please log in.');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('email username'); // Fetch only required fields
    if (!req.user) return res.status(404).json('User not found.');
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json('Session expired. Please log in again.');
    }
    res.status(403).json('Invalid token');
  }
};
