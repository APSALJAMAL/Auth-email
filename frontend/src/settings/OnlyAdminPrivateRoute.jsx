import { useSelector } from 'react-redux';
import { Outlet, Navigate } from 'react-router-dom';

export default function OnlyAdminPrivateRoute() {
  const { currentUser } = useSelector((state) => state.user);

  // Allow access for 'admin' and 'owner' roles
  return currentUser && (currentUser.role === 'admin' || currentUser.role === 'owner') ? (
    <Outlet />
  ) : (
    <Navigate to="/sign-in" />
  );
}
