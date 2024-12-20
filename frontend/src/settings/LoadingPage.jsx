 import React from 'react';
import { Triangle } from 'react-loader-spinner'; // Import the Triangle component

export default function LoadingPage() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-white dark:bg-gray-900">
      <Triangle
        visible={true}
        height="120" // Increased height
        width="120" // Increased width
        color="#a855f7" // Purple-500 color
        ariaLabel="triangle-loading"
        wrapperStyle={{}}
        wrapperClass=""
      />
      
    </div>
  );
}
