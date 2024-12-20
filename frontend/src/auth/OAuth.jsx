import { Button } from 'flowbite-react';
import { AiFillGoogleCircle } from 'react-icons/ai';
import { GoogleAuthProvider, signInWithPopup, getAuth } from 'firebase/auth';
import { app } from '../redux/firebase';
import { useDispatch } from 'react-redux';
import { signInSuccess, signInFailure } from '../redux/user/userSlice';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify'; // Import Toastify
import 'react-toastify/dist/ReactToastify.css'; // Import Toastify styles

export default function OAuth({ setLoading }) {
  const auth = getAuth(app);
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const handleGoogleClick = async () => {
    const provider = new GoogleAuthProvider();
    provider.setCustomParameters({ prompt: 'select_account' });

    try {
      setLoading(true); // Set loading to true before sign-in
      const resultsFromGoogle = await signInWithPopup(auth, provider);
      
      // POST the Google user data to the backend
      const res = await fetch('/api/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: resultsFromGoogle.user.displayName,
          email: resultsFromGoogle.user.email,
          googlePhotoUrl: resultsFromGoogle.user.photoURL,
        }),
      });

      const data = await res.json();

      // Handle responses: block (403), success (200), etc.
      if (res.status === 403) {
        dispatch(signInFailure(data.message)); // Dispatch failure with block message
        toast.error(data.message); // Use Toastify for error notification
      } else if (res.ok) {
        dispatch(signInSuccess(data)); // Dispatch success
        toast.success('Sign-in successful!'); // Use Toastify for success notification
        navigate('/'); // Navigate to home page
      }
    } catch (error) {
      console.error(error);
      toast.error('An error occurred during Google sign-in'); // Error notification
    } finally {
      setLoading(false); // Reset loading state after completion
    }
  };

  return (
    <Button type='button' gradientDuoTone='pinkToOrange' outline onClick={handleGoogleClick}>
      <AiFillGoogleCircle className='w-6 h-6 mr-2' />
      Continue with Google
    </Button>
  );
}
