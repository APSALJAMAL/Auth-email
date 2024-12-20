import React, { useEffect } from "react";
import BlogLogo from "../assets/logo.jpg";

const SplashScreen = ({ setLoading }) => {
  useEffect(() => {
    const timer = setTimeout(() => {
      setLoading(false); // Hide the splash screen after 2 seconds
    }, 2000);
    return () => clearTimeout(timer);
  }, [setLoading]);

  return (
    <div className="flex justify-center items-center min-h-screen flex-col dark:bg-gray-900 bg-gray-100">
      {/* Logo with shadow */}
      
        <img
          src={BlogLogo}
          alt="App Logo"
          className="w-80 h-80 "
        />
      

      {/* Copyright Footer */}
      <footer className="absolute bottom-4 dark:text-gray-200 dark:bg-gray-900 bg-white text-gray-700 text-sm">
        <p>&copy; 2024 Jamal's Company. All rights reserved.</p>
      </footer>
    </div>
  );
};

export default SplashScreen;
