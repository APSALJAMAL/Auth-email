import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Button, Label, Spinner, TextInput } from 'flowbite-react';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import BlogLogo from '../assets/logo.jpg';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setLoading(true);

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
      toast.error('Please enter a valid email address');
      setLoading(false);
      return;
    }

    try {
      await axios.post('/api/auth/forgot-password', { email });

      toast.success('OTP sent to your email. Please check your inbox.');
      navigate(`/validate-otp?email=${encodeURIComponent(email)}`);
    } catch (err) {
      const errorMessage =
        err.response?.data?.message || 'Unable to send OTP. Please try again.';
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="flex p-9 max-w-md mx-auto flex-col md:flex-row md:items-center gap-5">
        <div className="flex-1">
          <form
            className="flex flex-col gap-4 p-6 rounded shadow-lg bg-white dark:bg-gray-800 w-80"
            onSubmit={handleForgotPassword}
          >
            <div className="flex justify-center">
              <img
                src={BlogLogo}
                alt="Logo"
                className="w-25 h-24 object-cover"
              />
            </div>
            <h2 className="text-2xl font-bold text-center text-gray-800 dark:text-white">
              Forgot Password
            </h2>

            <div>
              <Label
                htmlFor="email"
                className="block text-sm font-medium text-gray-700 dark:text-gray-300"
              >
                Enter your email
              </Label>
              <TextInput
                type="email"
                placeholder="name@company.com"
                id="email"
                aria-label="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <Button
              type="submit"
              className="transition-all duration-300"
              gradientDuoTone="purpleToPink"
              disabled={loading}
            >
              {loading ? (
                <>
                  <Spinner size="sm" />
                  <span className="pl-2">Sending...</span>
                </>
              ) : (
                'Send OTP'
              )}
            </Button>
          </form>
        </div>
      </div>

      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="colored"
      />
    </div>
  );
};

export default ForgotPassword;
