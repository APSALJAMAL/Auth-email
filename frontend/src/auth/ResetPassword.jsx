import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import PasswordStrengthMeter from './PasswordStrengthMeter';
import { Button, Label, TextInput } from 'flowbite-react';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import BlogLogo from '../assets/logo.jpg';

const ResetPassword = () => {
  const { email: emailFromUrl } = useParams();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleResetPassword = async (e) => {
    e.preventDefault();

    if (newPassword.trim() !== confirmPassword.trim()) {
      toast.error("Passwords do not match.");
      return;
    }

    if (newPassword.length < 6) {
      toast.error("Password must be at least 6 characters long.");
      return;
    }

    try {
      setLoading(true);

      const response = await axios.post(`/api/auth/reset-password/${emailFromUrl}`, { password: newPassword.trim() });

      if (response.status === 200) {
        toast.success(response.data.message);
        setNewPassword('');
        setConfirmPassword('');

        setTimeout(() => {
          navigate('/sign-in');
        }, 2000);
      }
    } catch (error) {
      console.error("Error resetting password:", error); // Log the error
      toast.error(error.response?.data?.message || "An error occurred while resetting the password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className='min-h-screen flex items-center justify-center'>
      <div className='flex p-9 max-w-md mx-auto flex-col md:flex-row md:items-center gap-5'>
        <div className='flex-1'>
          <form onSubmit={handleResetPassword} className="flex flex-col gap-4 p-6 rounded shadow-2xl drop-shadow-lg filter shadow-gray-800 dark:shadow-purple-500  dark:shadow-2xl w-80">
            <div className='flex justify-center'>
              <img
                src={BlogLogo}
                alt='Logo'
                className='w-25 h-24 object-cover'
              />
            </div>
            <h2 className="text-2xl font-bold text-center">Reset Password</h2>

            <div className="mb-4">
              <Label className="block text-sm font-medium text-gray-700" htmlFor="email">Email</Label>
              <TextInput
                type="email"
                placeholder='name@company.com'
                id="email"
                value={emailFromUrl}
                readOnly
                required
                disabled={loading}
              />
            </div>

            <div className="mb-4">
              <Label className="block text-sm font-medium text-gray-700" htmlFor="newPassword">New Password</Label>
              <TextInput
                type="password"
                placeholder='**********'
                id="newPassword"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                disabled={loading}
              />
              <PasswordStrengthMeter password={newPassword} />
            </div>

            <div className="mb-6">
              <Label className="block text-sm font-medium text-gray-700" htmlFor="confirmPassword">Confirm Password</Label>
              <TextInput
                type="password"
                placeholder='**********'
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                disabled={loading}
              />
            </div>

            <Button
              type="submit"
              gradientDuoTone='purpleToPink'
              className={`w-full ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
              disabled={loading}
            >
              {loading ? "Resetting..." : "Reset Password"}
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

export default ResetPassword;
