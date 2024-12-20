import { useSelector } from 'react-redux';
import { Outlet, Navigate } from 'react-router-dom';

export default function OnlyOwnerPrivateRoute() {
  const { currentUser } = useSelector((state) => state.user);

  // Allow access for 'owner' only
  return currentUser && currentUser.role === 'owner' ? (
    <Outlet />
  ) : (
    <Navigate to="/sign-in" />
  );
}
