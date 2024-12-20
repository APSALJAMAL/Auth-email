import { Button, Label, Spinner, TextInput } from 'flowbite-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { signInStart, signInSuccess, signInFailure } from '../redux/user/userSlice';
import OAuth from './OAuth';
import LoadingPage from '../settings/LoadingPage'; // Adjust the import path as necessary
import { ToastContainer, toast } from 'react-toastify'; // Import Toastify
import 'react-toastify/dist/ReactToastify.css'; // Import Toastify CSS
import BlogLogo from '../assets/logo.jpg';

export default function SignIn() {
  const [formData, setFormData] = useState({});
  const { loading } = useSelector((state) => state.user);
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false); // Local loading state for redirect

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.id]: e.target.value.trim() });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.email || !formData.password) {
      return toast.error('Please fill all the fields');
    }
    try {
      dispatch(signInStart());
      const res = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await res.json();

      if (res.status === 403) {
        toast.error(data.message); // Show block message
        dispatch(signInFailure(data.message));
        return;
      }

      if (!res.ok || data.success === false) {
        toast.error(data.message || 'Sign in failed'); // Show error message
        dispatch(signInFailure(data.message || 'Sign in failed'));
        return;
      }

      dispatch(signInSuccess(data));
      toast.success('Sign in successful!'); // Show success message
      setIsLoading(true); // Set loading for redirect

      // Redirect to validate-phone-otp after a short delay
      setTimeout(() => {
        setIsLoading(false); // Ensure local loading state is reset
        navigate('/');
      }, 1000);
    } catch (error) {
      toast.error(error.message); // Show error message
      dispatch(signInFailure(error.message));
    }
  };

  // Show loading spinner if loading from Redux or local loading state
  if (loading || isLoading) {
    return <LoadingPage />;
  }

  return (
    <div className='min-h-screen flex items-center justify-center bg-red'>
      <div className='flex p-9 max-w-md mx-auto flex-col md:flex-row md:items-center gap-5'>
        <div className='flex-1'>
          <form
            className='flex flex-col gap-4 p-6 rounded drop-shadow-lg filter shadow-gray-800 shadow-2xl dark:shadow-purple-500 dark:shadow-2xl w-80'
            onSubmit={handleSubmit}
          >
            <div className='flex justify-center'>
              <img
                src={BlogLogo}
                alt='Logo'
                className='w-25 h-24  object-cover'
              />
            </div>
            <div>
              <Label value='Your email' />
              <TextInput
                type='email'
                placeholder='name@company.com'
                id='email'
                onChange={handleChange}
              />
            </div>
            <div>
              <Label value='Your password' />
              <TextInput
                type='password'
                placeholder='**********'
                id='password'
                onChange={handleChange}
              />
            </div>
            <div className='flex flex-auto gap-2 text-sm'>
              <span>Forgot your password?</span>
              <Link to='/forgot-password' className='text-blue-500'>
                Click Here
              </Link>
            </div>
            <Button
              gradientDuoTone='purpleToPink'
              type='submit'
              disabled={loading}
            >
              {loading ? (
                <>
                  <Spinner size='sm' />
                  <span className='pl-3'>Loading...</span>
                </>
              ) : (
                'Sign In'
              )}
            </Button>
            <OAuth setLoading={setIsLoading} /> {/* Pass setLoading to OAuth */}
            <div className='flex gap-2 text-sm mt-5'>
              <span>Don't have an account?</span>
              <Link to='/sign-up' className='text-blue-500'>
                Sign Up
              </Link>
            </div>
          </form>
        </div>
      </div>

      <ToastContainer position='top-right' autoClose={3000} hideProgressBar />
    </div>
  );
}
