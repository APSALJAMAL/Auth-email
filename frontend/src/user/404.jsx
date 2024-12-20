import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from 'flowbite-react';

const NotFoundPage = () => {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-900 p-4">
      <div className="text-center">
        <h1 className="text-6xl font-bold text-gray-900 dark:text-gray-100">404</h1>
        <p className="mt-4 text-xl text-gray-700 dark:text-gray-300">
          Sorry, we couldn't find that page!
        </p>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          It seems the page you're looking for has either been moved or doesn't exist.
        </p>
        <div className="flex justify-center mt-6">
          <Link to="/">
            <Button gradientDuoTone="purpleToPink">
              Return to Home
            </Button>
          </Link>
        </div>
        <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
          If you believe this is an error, please <Link to="/contact" className="text-blue-500">contact us</Link>.
        </p>
      </div>
    </div>
  );
};

export default NotFoundPage;
