import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { useEffect, useState } from 'react';
import Home from './admin/Home';

import SignIn from './auth/SignIn';
import Dashboard from './admin/Dashboard';
import SignUp from './auth/SignUp';
import Header from './admin/Header';
import Footer from './admin/Footer';
import PrivateRoute from './settings/PrivateRoute';
import OnlyAdminPrivateRoute from './settings/OnlyAdminPrivateRoute';
import Search from './admin/Search';
import NotFoundPage from './user/404';
import ForgotPassword from './auth/ForgotPassword';
import ValidateOTP from './auth/ValidateOtp';

import ResetPassword from './auth/ResetPassword';
import LoadingPage from './settings/LoadingPage';
import SplashScreen from './settings/SplashScreen'; // Import SplashScreen
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import Contact from './user/Contact';
import About from './user/About';
import Post from './user/Post';
import Category from './user/Category';
import OnlyOwnerPrivateRoute from './settings/OnlyOwnerPrivateRoute';
import UserDetails from './admin/UserDetails';
import { RegisterOtp } from './auth/RegisterOtp';
import OwnerUsers from './admin/OwnerUsers';
import OwnerAllDetails from './admin/OwnerAllDetails';




export default function App() {
  const [loading, setLoading] = useState(true); // State to track loading status
  const [showSplash, setShowSplash] = useState(false); // State for splash screen

  useEffect(() => {
    // Check if the user has seen the splash screen
    const hasSeenSplash = sessionStorage.getItem('hasSeenSplash'); // Use sessionStorage to track state

    if (!hasSeenSplash) {
      setShowSplash(true);
      sessionStorage.setItem('hasSeenSplash', 'true'); // Set flag in sessionStorage
    }

    const splashTimer = setTimeout(() => {
      setShowSplash(false);
    }, 2000); // Show splash screen for 2 seconds

    const loadingTimer = setTimeout(() => {
      setLoading(false); // Hide loading spinner after total loading time
    }, 5000); // 5 seconds total (2 for splash + 3 for loading)

    return () => {
      clearTimeout(splashTimer);
      clearTimeout(loadingTimer);
    };
  }, []);

  return (
    <BrowserRouter>

      
      <ToastContainer /> {/* Toastify container for notifications */}
      {showSplash ? (
        <SplashScreen /> // Show splash screen if showSplash is true
      ) : loading ? (
        <LoadingPage /> // Show loading spinner if loading is true
      ) : (
        <>
          <Header />
          <Routes>
          <Route path='/' element={<Home />} />
            <Route path='/sign-in' element={<SignIn setLoading={setLoading} />} />
            <Route path='/sign-up' element={<SignUp />} />
            <Route path='/register-otp/:email' element={<RegisterOtp />} />
            <Route path='/forgot-password' element={<ForgotPassword />} />
            <Route path='/validate-otp' element={<ValidateOTP />} />
            <Route path='/reset-password/:email' element={<ResetPassword />} />
            <Route path='*' element={<NotFoundPage />} />



            <Route element={<PrivateRoute />}>
            <Route path='/contact' element={<Contact />} />
            <Route path='/about' element={<About />} />
            <Route path='/getposts' element={<Post />} />
            <Route path='/category' element={<Category />} />
            <Route path='/search' element={<Search />} />
            <Route path='/dashboard' element={<Dashboard />} />
            
            </Route>

            <Route element={<OnlyAdminPrivateRoute />}>
            <Route path='/userdetails/:id' element={<UserDetails />} />
            </Route>

            <Route element={<OnlyOwnerPrivateRoute />}>
            <Route path='/owneralldetails/:id' element={<OwnerAllDetails />} /> 
            </Route>

          </Routes>
          <Footer />
        </>
      )}
    </BrowserRouter>
  );
}
