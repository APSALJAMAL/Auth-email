import express from 'express';
import { 
    google,
    signin,
    signup,
    forgotPassword,
    validateOtp,
    resendOtp,
    resetPassword,
    getOldPassword,
    signupresendOtp,
    signupvalidateOtp,

} from '../controllers/auth.controller.js';

const router = express.Router();


router.post('/signup', signup);
router.post('/signupvalidate-otp/:email', signupvalidateOtp);

router.post('/signupresend-otp', signupresendOtp);
router.post('/signin', signin);

router.post('/google', google);

router.post('/forgot-password', forgotPassword);
router.post('/validate-otp', validateOtp);
router.post('/resend-otp', resendOtp);
router.post('/reset-password/:email', resetPassword);

router.post('/get-old-password', getOldPassword);

export default router;
