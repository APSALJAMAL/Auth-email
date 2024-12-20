import { Avatar, Button, Dropdown, Navbar, TextInput } from 'flowbite-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AiOutlineSearch } from 'react-icons/ai';
import { FaMoon, FaSun } from 'react-icons/fa';
import { useSelector, useDispatch } from 'react-redux';
import { toggleTheme } from '../redux/theme/themeslice.js';
import { signoutSuccess } from '../redux/user/userSlice';
import { useEffect, useState } from 'react';
import BlogLogo from '../assets/logo.jpg';
import { House, BookCheck, Layers3, Radar, Album } from 'lucide-react';

export default function Header() {
  const path = useLocation().pathname;
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { currentUser } = useSelector((state) => state.user);
  const { theme } = useSelector((state) => state.theme);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    const urlParams = new URLSearchParams(location.search);
    const searchTermFromUrl = urlParams.get('searchTerm');
    if (searchTermFromUrl) {
      setSearchTerm(searchTermFromUrl);
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

  const handleSubmit = (e) => {
    e.preventDefault();
    const urlParams = new URLSearchParams(location.search);
    urlParams.set('searchTerm', searchTerm);
    const searchQuery = urlParams.toString();
    navigate(`/search?${searchQuery}`);
  };

  // Mobile search bar click handler
  const handleMobileSearch = () => {
    navigate(`/search?searchTerm=${searchTerm}`);
  };

  return (
    <>
      {/* Top Navbar */}
      <Navbar className="fixed top-0 left-0 right-0 z-50 border-b-2 bg-white dark:bg-gray-800">
        <div className="self-center whitespace-nowrap text-sm sm:text-xl font-semibold dark:text-white">
          <Link to="/" className="flex items-center">
            <img
              src={BlogLogo}
              alt="Jamal's Blog Logo"
              className="h-12 w-12  mr-4"
            />
            <h1 className="text-xl sm:text-xl font-semibold dark:text-white">Jamal's Auth</h1>
          </Link>
        </div>
        <form onSubmit={handleSubmit} className="hidden lg:flex">
          <TextInput
            type="text"
            placeholder="Search..."
            rightIcon={AiOutlineSearch}
            className="hidden lg:inline"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </form>
        <Button className="w-12 h-10 lg:hidden" color="gray" pill onClick={handleMobileSearch}>
          <AiOutlineSearch />
        </Button>
        <div className="flex gap-8 md:order-2">
          {/* Dark Mode Toggle on the Top Bar */}
          <Button
            className="w-12 h-10"
            color="gray"
            pill
            onClick={() => dispatch(toggleTheme())}
          >
            {theme === 'light' ? <FaSun /> : <FaMoon />}
          </Button>
          {currentUser ? (
            <Dropdown
              arrowIcon={false}
              inline
              label={
                <Avatar alt="user" img={currentUser.profilePicture} rounded />
              }
            >
              <Dropdown.Header>
                <span className="block text-sm">@{currentUser.username}</span>
                <span className="block text-sm font-medium truncate">
                  {currentUser.email}
                </span>
              </Dropdown.Header>
              <Link to={'/dashboard?tab=profile'}>
                <Dropdown.Item>Profile</Dropdown.Item>
              </Link>
              <Dropdown.Divider />
              <Dropdown.Item onClick={handleSignout}>Sign out</Dropdown.Item>
            </Dropdown>
          ) : (
            <Link to="/sign-in">
              <Button gradientDuoTone="purpleToBlue" outline>
                Sign In
              </Button>
            </Link>
          )}
        </div>
        {/* Navbar Collapse for larger screens */}
        <Navbar.Collapse className="hidden lg:flex">
          <Navbar.Link active={path === '/'} as={'div'}>
            <Link to="/">Home</Link>
          </Navbar.Link>
          <Navbar.Link active={path === '/getposts'} as={'div'}>
            <Link to="/getposts">Posts</Link>
          </Navbar.Link>
          <Navbar.Link active={path === '/category'} as={'div'}>
            <Link to="/category">Category</Link>
          </Navbar.Link>
          <Navbar.Link active={path === '/about'} as={'div'}>
            <Link to="/about">About</Link>
          </Navbar.Link>
          <Navbar.Link active={path === '/dashboard'} as={'div'}>
            <Link to="/dashboard">Dashboard</Link>
          </Navbar.Link>
        </Navbar.Collapse>
      </Navbar>

      {/* Bottom Navigation for Mobile View */}
      <div className="fixed bottom-0 left-0 right-0 z-50 bg-white dark:bg-gray-800 border-t-2 flex justify-around items-center py-2 lg:hidden">
        <Link
          to="/"
          className={`flex flex-col items-center ${
            path === '/' ? 'text-purple-600' : 'text-gray-600 dark:text-white'
          }`}
        >
          <House size={24} />
          <span className="text-xs">Home</span>
        </Link>
        <Link
          to="/getposts"
          className={`flex flex-col items-center ${
            path === '/getposts' ? 'text-purple-600' : 'text-gray-600 dark:text-white'
          }`}
        >
          <BookCheck size={24} />
          <span className="text-xs">Posts</span>
        </Link>
        <Link
          to="/category"
          className={`flex flex-col items-center ${
            path === '/category' ? 'text-purple-600' : 'text-gray-600 dark:text-white'
          }`}
        >
          <Layers3 size={24} />
          <span className="text-xs">Category</span>
        </Link>
        <Link
          to="/about"
          className={`flex flex-col items-center ${
            path === '/about' ? 'text-purple-600' : 'text-gray-600 dark:text-white'
          }`}
        >
          <Album size={24} />
          <span className="text-xs">About</span>
        </Link>
        <Link
          to="/dashboard"
          className={`flex flex-col items-center ${
            path === '/dashboard' ? 'text-purple-600' : 'text-gray-600 dark:text-white'
          }`}
        >
          <Radar size={24} />
          <span className="text-xs">Dashboard</span>
        </Link>

      </div>

      {/* Main Content with margin for the fixed navbar */}
      <div className="pt-16">
        {/* Your main content goes here */}
      </div>
    </>
  );
}
