import { useSelector } from 'react-redux';

export default function ThemeProvider({ children }) {
  const { theme } = useSelector((state) => state.theme);

  return (
    <div className={theme || 'dark'}> {/* Default to 'dark' theme */}
      <div className='dark:text-gray-200 dark:bg-gray-900 bg-white text-gray-700 min-h-screen'>
        {children}
      </div>
    </div>
  );
}
