import { Sidebar } from 'flowbite-react';
import {
  HiUser,
  HiArrowSmRight,
  HiDocumentText,
  HiOutlineUserGroup,
  HiAnnotation,
  HiChartPie,
} from 'react-icons/hi';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { signoutSuccess } from '../redux/user/userSlice';
import { useDispatch } from 'react-redux';
import { useSelector } from 'react-redux';
import { useLocation } from 'react-router-dom'; // Import useLocation here

export default function DashSidebar({ onTabClick }) {
  const location = useLocation(); // Use useLocation inside DashSidebar
  const dispatch = useDispatch();
  const { currentUser } = useSelector((state) => state.user);
  const [tab, setTab] = useState('');

  useEffect(() => {
    const urlParams = new URLSearchParams(location.search);
    const tabFromUrl = urlParams.get('tab');
    if (tabFromUrl) {
      setTab(tabFromUrl);
    }
  }, [location.search]);

  const handleSignout = async () => {
    try {
      const res = await fetch('/api/user/signout', {
        method: 'POST',
      });
      const data = await res.json();
      if (!res.ok) {
        console.log(data.message);
      } else {
        dispatch(signoutSuccess());
      }
    } catch (error) {
      console.log(error.message);
    }
  };

  const handleTabClick = (newTab) => {
    setTab(newTab);
    onTabClick(newTab); // Close the sidebar when a tab is clicked
  };

  return (
    <Sidebar className="w-full md:w-56 shadow-gray-800 shadow-lg dark:shadow-purple-500 dark:shadow-lg">
      <Sidebar.Items>
        <Sidebar.ItemGroup className="flex flex-col gap-1">
          {currentUser && (
            <>
              {/* Dashboard Tab */}
              {(currentUser.role === 'admin' || currentUser.role === 'owner') && (
                <Link
                  to="/dashboard?tab=dash"
                  onClick={() => handleTabClick('dash')}
                >
                  <Sidebar.Item
                    active={tab === 'dash' || !tab}
                    icon={HiChartPie}
                    as="div"
                    className="shadow-gray-800 shadow-lg dark:shadow-purple-500 dark:shadow-lg"
                  >
                    Dashboard
                  </Sidebar.Item>
                </Link>
              )}

              {/* Profile Tab */}
              <Link
                to="/dashboard?tab=profile"
                onClick={() => handleTabClick('profile')}
              >
                <Sidebar.Item
                  active={tab === 'profile'}
                  icon={HiUser}
                  label={
                    currentUser.role === 'owner'
                      ? 'Owner'
                      : currentUser.role === 'admin'
                      ? 'Admin'
                      : 'User'
                  }
                  labelColor="dark"
                  as="div"
                  className="shadow-gray-800 shadow-lg dark:shadow-purple-500 dark:shadow-lg"
                >
                  Profile
                </Sidebar.Item>
              </Link>

              {/* Users Tab (Admin Only) */}
              {currentUser.role === 'admin' && (
                <Link
                  to="/dashboard?tab=users"
                  onClick={() => handleTabClick('users')}
                >
                  <Sidebar.Item
                    active={tab === 'users'}
                    icon={HiOutlineUserGroup}
                    as="div"
                    className="shadow-gray-800 shadow-lg dark:shadow-purple-500 dark:shadow-lg"
                  >
                    Users
                  </Sidebar.Item>
                </Link>
              )}

              {/* Custom Role-Based Tabs */}
              {currentUser.role === 'owner' && (
                <Link
                  to="/dashboard?tab=ownerusers"
                  onClick={() => handleTabClick('ownerusers')}
                >
                  <Sidebar.Item
                    active={tab === 'owner'}
                    icon={HiDocumentText}
                    as="div"
                    className="shadow-gray-800 shadow-lg dark:shadow-purple-500 dark:shadow-lg"
                  >
                    owner Panel
                  </Sidebar.Item>
                </Link>
              )}

              {currentUser.role === 'editor' && (
                <Link
                  to="/dashboard?tab=editor"
                  onClick={() => handleTabClick('editor')}
                >
                  <Sidebar.Item
                    active={tab === 'editor'}
                    icon={HiAnnotation}
                    as="div"
                    className="shadow-gray-800 shadow-lg dark:shadow-purple-500 dark:shadow-lg"
                  >
                    Editor Panel
                  </Sidebar.Item>
                </Link>
              )}
            </>
          )}

          {/* Sign Out */}
          <Sidebar.Item
            icon={HiArrowSmRight}
            onClick={handleSignout}
            className="cursor-pointer shadow-gray-800 shadow-lg dark:shadow-purple-500 dark:shadow-lg"
          >
            Sign Out
          </Sidebar.Item>
        </Sidebar.ItemGroup>
      </Sidebar.Items>
    </Sidebar>
  );
}
