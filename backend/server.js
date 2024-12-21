import express from 'express';
import { connectDB } from "./db/connectDB.js";
import dotenv from 'dotenv';
import cors from'cors';
import userRoutes from './routes/user.route.js';
import authRoutes from './routes/auth.route.js';
import './utils/cronCleanup.js'; // Import the cron cleanup task


import cookieParser from 'cookie-parser';
import path from 'path';



dotenv.config();




const __dirname = path.resolve();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST", "DELETE", "PUT"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());
app.use(cookieParser());

app.listen(PORT, () => {
	connectDB();
	console.log("Server is running on port: ", PORT);
});

app.use('/api/user', userRoutes);
app.use('/api/auth', authRoutes);

app.use(express.static(path.join(__dirname, '/frontend/dist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "dist", "index.html"));
});

app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  res.status(statusCode).json({
    success: false,
    statusCode,
    message,
  });
});




