import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import { Button, Label, Spinner, TextInput } from 'flowbite-react';
import BlogLogo from '../assets/logo.jpg';
import { toast, ToastContainer } from 'react-toastify'; 
import 'react-toastify/dist/ReactToastify.css'; 

const ValidateOTP = () => {
  const [otp, setOtp] = useState(new Array(6).fill('')); // Array of 6 elements for OTP
  const [loading, setLoading] = useState(false);
  const [timer, setTimer] = useState(120); // 2 minutes in seconds
  const [isResendDisabled, setIsResendDisabled] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();
  const inputRefs = useRef([]); // Create a refs array

  // Extract email from query parameters
  const queryParams = new URLSearchParams(location.search);
  const email = queryParams.get('email');

  useEffect(() => {
    if (timer > 0) {
      const interval = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);

      return () => clearInterval(interval);
    } else {
      setIsResendDisabled(false);
    }
  }, [timer]);

  const handleChange = (element, index) => {
    const value = element.value;

    // Only allow numbers
    if (!/^\d*$/.test(value)) {
      return;
    }

    // Update the OTP state
    setOtp([...otp.map((d, idx) => (idx === index ? value : d))]);

    // Move to the next input box automatically if the value is not empty
    if (value && index < otp.length - 1) {
      inputRefs.current[index + 1].focus(); // Focus next input using refs
    }

    // Move to the previous input box if the input is empty and the index is not zero
    if (!value && index > 0) {
      inputRefs.current[index - 1].focus(); // Focus previous input using refs
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const finalOtp = otp.join(''); // Combine OTP array into a single string

    try {
      const response = await axios.post('/api/auth/validate-otp', { otp: finalOtp, email }); // Send email with OTP
      toast.success(response.data.message); // Show success message
      setLoading(false);
      navigate(`/reset-password/${email}`); // Navigate to reset password page with email
    } catch (error) {
      toast.error(error.response?.data?.message || 'Invalid OTP. Please try again.'); // Show error message
      setLoading(false);
    }
  };

  const handleResendOTP = async () => {
    setLoading(true);

    try {
      await axios.post('/api/auth/resend-otp', { email }); // Send email with resend OTP request
      toast.success('OTP sent successfully'); // Show success message for OTP sent
      setLoading(false);
      setOtp(new Array(6).fill('')); // Reset the OTP inputs
      setTimer(120); // Reset timer to 2 minutes
      setIsResendDisabled(true);
    } catch (error) {
      toast.error(error.response?.data?.message || 'Error resending OTP. Please try again.'); // Show error message for OTP resend failure
      setLoading(false);
    }
  };

  const formatTime = (timeInSeconds) => {
    const minutes = Math.floor(timeInSeconds / 60);
    const seconds = timeInSeconds % 60;
    return `${minutes}:${seconds < 10 ? '0' + seconds : seconds}`;
  };

  return (
    <div className='min-h-screen flex items-center justify-center'>
      <div className='flex p-9 max-w-md mx-auto flex-col md:flex-row md:items-center gap-5'>
        <div className='flex-1'>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4 p-6 rounded shadow-2xl drop-shadow-lg filter shadow-gray-800 dark:shadow-purple-500 w-80">
            <div className='flex justify-center'>
              <img
                src={BlogLogo}
                alt='Logo'
                className='w-25 h-24 object-cover'
              />
            </div>
            <h2 className="text-2xl font-bold text-center">Validate OTP</h2>
            <Label className="block text-sm font-medium text-gray-700">Enter your OTP</Label>

            {/* OTP Input Boxes */}
            <div className="flex justify-center gap-2">
              {otp.map((data, index) => (
                <TextInput
                  key={index}
                  type="text"
                  maxLength="1"
                  value={data}
                  onChange={(e) => handleChange(e.target, index)}
                  ref={(el) => inputRefs.current[index] = el} // Assign the ref
                  className="w-10 h-10 text-center text-xl"
                />
              ))}
            </div>

            <Button
              type="submit"
              gradientDuoTone='purpleToPink'
              disabled={loading}
            >
              {loading ? (
                <><Spinner size="sm" /><span className="pl-3">Validating...</span></>
              ) : (
                'Validate OTP'
              )}
            </Button>

            <div className="mt-2 text-center">
              <span className="font-bold text-red-500">
                Resend OTP in: <span className="font-mono">{formatTime(timer)}</span>
              </span>
            </div>

            {!isResendDisabled && (
              <button
                type="button"
                onClick={handleResendOTP}
                className="mt-4 text-blue-500 hover:underline w-full"
              >
                Resend OTP
              </button>
            )}
          </form>
        </div>
      </div>
      {/* Add the ToastContainer here */}
      <ToastContainer />
    </div>
  );
};

export default ValidateOTP;
