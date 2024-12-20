import { Alert, Button, Label, Spinner, TextInput } from 'flowbite-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import OAuth from './OAuth';
import PasswordStrengthMeter from './PasswordStrengthMeter';
import BlogLogo from '../assets/logo.jpg'; // Ensure the path to your logo is correct
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css'; // Import Toastify CSS

export default function SignUp() {
  const [formData, setFormData] = useState({});
  const [loading, setLoading] = useState(false);
  const [password, setPassword] = useState(''); // Track password separately for strength meter
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { id, value } = e.target;
    setFormData((prev) => ({ ...prev, [id]: value.trim() }));

    if (id === 'password') {
      setPassword(value); // Update password for strength meter
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!formData.username || !formData.email || !formData.password) {
      return toast.error('Please fill out all fields.');
    }

    try {
      setLoading(true);
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      const data = await res.json();
      if (!res.ok) {
        return toast.error(data.message || 'Something went wrong.');
      }

      toast.success('Successfully signed up!');
      const encodedEmail = encodeURIComponent(btoa(formData.email)); // Base64 encode and URI encode
      navigate(`/register-otp/${encodedEmail}`);
    } catch (error) {
      toast.error(error.message || 'Error occurred while signing up.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="flex p-3 max-w-md mx-auto flex-col md:flex-row md:items-center gap-5">
        <div className="flex-1">
          <form
            className="flex flex-col gap-4 p-6 rounded shadow-2xl drop-shadow-lg filter shadow-gray-800 dark:shadow-purple-500 dark:shadow-2xl w-80 mx-auto"
            onSubmit={handleSubmit}
          >
            {/* Logo section */}
            <div className="flex justify-center mb-4">
              <img
                src={BlogLogo}
                alt="Logo"
                className="w-25 h-24 object-cover"
              />
            </div>

            <div>
              <Label value="Your username" />
              <TextInput
                type="text"
                placeholder="Username"
                id="username"
                onChange={handleChange}
              />
            </div>

            <div>
              <Label value="Your email" />
              <TextInput
                type="email"
                placeholder="name@company.com"
                id="email"
                onChange={handleChange}
              />
            </div>

            <div>
              <Label value="Your password" />
              <TextInput
                type="password"
                placeholder="Password"
                id="password"
                onChange={handleChange}
              />
              <PasswordStrengthMeter password={password} />
            </div>

            <Button
              gradientDuoTone="purpleToPink"
              type="submit"
              disabled={loading}
            >
              {loading ? (
                <>
                  <Spinner size="sm" />
                  <span className="pl-3">Loading...</span>
                </>
              ) : (
                'Sign Up'
              )}
            </Button>

            <OAuth setLoading={setLoading} />

            <div className="flex gap-2 text-sm mt-5">
              <span>Have an account?</span>
              <Link to="/sign-in" className="text-blue-500">
                Sign In
              </Link>
            </div>
          </form>
        </div>
      </div>
      <ToastContainer />
    </div>
  );
}
