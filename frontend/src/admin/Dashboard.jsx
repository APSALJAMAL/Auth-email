import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import DashSidebar from './DashSidebar';
import DashProfile from './DashProfile';
import OwnerUsers from './OwnerUsers';
import DashUsers from './DashUsers';

import DashboardComp from './DashboardComp';
import { HiArrowRight } from 'react-icons/hi';

export default function Dashboard() {
  const location = useLocation();  // Use useLocation here
  const [tab, setTab] = useState('profile'); // Default tab is 'profile'
  const [isSidebarOpen, setIsSidebarOpen] = useState(false); // State to toggle sidebar

  useEffect(() => {
    const urlParams = new URLSearchParams(location.search);
    const tabFromUrl = urlParams.get('tab');
    if (tabFromUrl) {
      setTab(tabFromUrl);
    }
  }, [location.search]);

  // Function to toggle sidebar
  const toggleSidebar = () => {
    setIsSidebarOpen((prev) => !prev);
  };

  const handleTabClick = (newTab) => {
    setTab(newTab);
    setIsSidebarOpen(false); // Close the sidebar when a tab is clicked
  };

  return (
    <div className='min-h-screen flex flex-col md:flex-row relative'>
      {/* Sidebar */}
      <div
        className={`fixed pt-16 md:pt-0 inset-y-0 left-0 z-40 md:relative md:w-56  bg-white shadow-lg transform ${
          isSidebarOpen ? 'translate-x-0' : '-translate-x-full'
        } transition-transform duration-300 ease-in-out md:translate-x-0`}
      >
        <DashSidebar onTabClick={handleTabClick} />  {/* Use DashSidebar without passing location */}
      </div>

      {/* Sidebar Toggle Button */}
      <div
        className={`md:hidden fixed top-18 left-4 z-40 ${
          isSidebarOpen ? 'left-[230px]' : 'left-4'
        } transition-all duration-300`}
      >
        <button
          className='bg-purple-500 text-white p-2  shadow-md focus:outline-none'
          onClick={toggleSidebar}
        >
          <HiArrowRight
            className={`transform ${isSidebarOpen ? 'rotate-180' : ''} transition-transform duration-300`}
          />
        </button>
      </div>

      {/* Main Content */}
      <div className='flex-1 p-5'>
        {/* Conditionally render components based on the 'tab' query param */}
        {tab === 'profile' && <DashProfile />}
        
        {tab === 'users' && <DashUsers />}

        {tab === 'ownerusers' && <OwnerUsers />}
        
        {tab === 'dash' && <DashboardComp />}
      </div>
    </div>
  );
}
