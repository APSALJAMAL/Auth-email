import React from 'react';
import BlogLogo from '../assets/logo.jpg'

const Contact = () => {

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-900 p-4">
      <div className="w-full max-w-md text-center">
        {/* Add the logo */}
        <div className='flex justify-center '>
            <img
              src={BlogLogo} // Replace with the actual path to your logo
              alt='Logo'
              className='w-40 h-40 rounded-full object-cover' // Tailwind CSS classes for a circular logo
            />
          </div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mt-6 mb-6">
          Contact Us
        </h2>

        <p className="text-gray-500 text-xs sm:text-sm">
          For inquiries, feel free to reach out to us at:
        </p>
        <p className="text-gray-700 dark:text-gray-300">
          Name: <strong>S Apsal Jamal </strong>
        </p>
        <p className="text-gray-700 dark:text-gray-300">
          Email: <strong>jamalapsal@gmail.com</strong>
        </p>
        <p className="text-gray-700 dark:text-gray-300">
          Phone: <strong>+91 77089 66487</strong>
        </p>

        <div className="mt-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
            In Case of Emergency
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Please contact us immediately at <strong>+91 77089 66487</strong> or email us at <strong>jamalapsal@gmail.com</strong>.
          </p>
          
        </div>

        
      </div>
    </div>
  );
};

export default Contact;
