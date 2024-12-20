// cronCleanup.js
import cron from 'node-cron';
import TempUser from '../models/tempuser.model.js';  // Import TempUser model

// Schedule task to run every minute to check for expired OTPs
cron.schedule('* * * * *', async () => {
  try {
    // Get the current time
    const currentTime = Date.now();

    // Calculate the expiration threshold for 6 minutes (in milliseconds)
    const expirationThreshold = currentTime - 6 * 60 * 1000;

    // Find and delete OTP records that have expired (more than 8 minutes old)
    const result = await TempUser.deleteMany({ otpExpires: { $lt: expirationThreshold } });

    console.log(`Expired OTP records cleared. ${result.deletedCount} records deleted.`);
  } catch (error) {
    console.error('Error during cleanup:', error);
  }
});
