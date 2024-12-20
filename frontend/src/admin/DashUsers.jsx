import { Modal, Table, Button, TextInput, Alert, Label } from 'flowbite-react';
import { useEffect, useState } from 'react';
import { useSelector } from 'react-redux';
import { HiOutlineExclamationCircle } from 'react-icons/hi';
import { useNavigate } from 'react-router-dom'; // Import useNavigate for navigation
import axios from 'axios';

export default function DashUsers() {
  const { currentUser } = useSelector((state) => state.user);
  const [users, setUsers] = useState([]);
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [dateQuery, setDateQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState(''); // State for role filter
  const [showMore, setShowMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const navigate = useNavigate(); // useNavigate hook for navigation

  useEffect(() => {
    const fetchUsers = async () => {
      setLoading(true);
      setError('');
      try {
        const res = await axios.get(`/api/user/getusers`);
        const filtered = res.data.users.filter(user => user.role !== 'owner');
        setUsers(filtered);
        setFilteredUsers(filtered);
        setShowMore(filtered.length === 9);
      } catch (error) {
        setError(error.message);
      } finally {
        setLoading(false);
      }
    };

    if (currentUser?.role === 'admin') {
      fetchUsers();
    } else {
      navigate('/'); // Redirect if not an admin
    }
  }, [currentUser, navigate]);

  const handleShowMore = async () => {
    const startIndex = users.length;
    setLoading(true);
    setError('');
    try {
      const res = await axios.get(`/api/user/getusers?startIndex=${startIndex}`);
      const filtered = res.data.users.filter(user => user.role !== 'owner');
      setUsers((prev) => [...prev, ...filtered]);
      setFilteredUsers((prev) => [...prev, ...filtered]);
      setShowMore(filtered.length === 9);
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (userId) => {
    setLoading(true);
    setError('');
    try {
      const res = await axios.delete(`/api/user/delete/${userId}`);
      if (res.status === 200) {
        setUsers((prev) => prev.filter((user) => user._id !== userId));
        setFilteredUsers((prev) => prev.filter((user) => user._id !== userId));
      }
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleBlockUnblockUser = async (userId, isBlocked) => {
    setLoading(true);
    setError('');
    try {
      const res = await axios.patch(`/api/user/${isBlocked ? 'unblock' : 'block'}/${userId}`);
      if (res.status === 200) {
        setUsers((prev) =>
          prev.map((user) =>
            user._id === userId ? { ...user, isBlocked: !isBlocked } : user
          )
        );
        setFilteredUsers((prev) =>
          prev.map((user) =>
            user._id === userId ? { ...user, isBlocked: !isBlocked } : user
          )
        );
      }
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateRole = async (userId, currentRole) => {
    const newRole = currentRole === 'admin' ? 'user' : 'admin';
    setLoading(true);
    setError('');
    try {
      const res = await axios.patch(`/api/user/updateRole/${userId}`, { role: newRole });
      if (res.status === 200) {
        setUsers((prev) =>
          prev.map((user) => (user._id === userId ? { ...user, role: newRole } : user))
        );
        setFilteredUsers((prev) =>
          prev.map((user) => (user._id === userId ? { ...user, role: newRole } : user))
        );
      }
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFilter = (query, dateRange, role) => {
    setSearchQuery(query);
    setDateQuery(dateRange);
    setRoleFilter(role); // Set role filter state

    const lowerQuery = query.toLowerCase();
    let filtered = users.filter((user) =>
      user.username.toLowerCase().includes(lowerQuery) ||
      user.email.toLowerCase().includes(lowerQuery) ||
      user.role.toLowerCase().includes(lowerQuery) ||
      (query.toLowerCase() === 'block' && user.isBlocked) ||
      (query.toLowerCase() === 'unblock' && !user.isBlocked)
    );

    if (role) {
      filtered = filtered.filter((user) => user.role === role);
    }

    if (dateRange) {
      if (dateRange.includes('-')) {
        const [startDateStr, endDateStr] = dateRange.split('-').map((date) => new Date(date.trim()));
        startDateStr.setHours(0, 0, 0, 0);
        endDateStr.setHours(23, 59, 59, 999);
        filtered = filtered.filter((user) => {
          const userDate = new Date(user.createdAt);
          return userDate >= startDateStr && userDate <= endDateStr;
        });
      } else {
        const dateFilter = new Date(dateRange);
        dateFilter.setHours(0, 0, 0, 0);
        filtered = filtered.filter((user) => {
          const userDate = new Date(user.createdAt);
          return userDate.toDateString() === dateFilter.toDateString();
        });
      }
    }

    setFilteredUsers(filtered);
  };

  const clearFilters = () => {
    setSearchQuery('');
    setDateQuery('');
    setRoleFilter('');
    setFilteredUsers(users);
  };

  return (
    <div className='table-auto overflow-x-scroll md:mx-auto p-3 scrollbar scrollbar-track-slate-100 scrollbar-thumb-slate-300 dark:scrollbar-track-slate-700 dark:scrollbar-thumb-slate-500'>
      {currentUser?.role === 'admin' && users.length > 0 ? (
        <>
          {error && <Alert color="failure">{error}</Alert>}
          {loading && <p>Loading...</p>}

          <div className="flex flex-col items-center gap-4 mb-4">
            <div className="flex flex-col w-full max-w-xl">
              <Label value='Filter' />
              <TextInput
                type='text'
                placeholder='Filter by username, email, role, block status (block/unblock)'
                value={searchQuery}
                onChange={(e) => handleFilter(e.target.value, dateQuery, roleFilter)}
                className='w-full mb-2'
              />
            </div>
            <div className="flex flex-col w-full max-w-xl">
              <Label value='Date Range' />
              <TextInput
                type='text'
                placeholder='Filter by date or date range (e.g., 10/8/2024 or 10/8/2024-10/11/2024)'
                value={dateQuery}
                onChange={(e) => handleFilter(searchQuery, e.target.value, roleFilter)}
                className='w-full mb-2'
              />
            </div>
            <div className="flex gap-4 mb-4">
              <Button onClick={() => handleFilter(searchQuery, dateQuery, 'user')}>User</Button>
              <Button onClick={() => handleFilter(searchQuery, dateQuery, 'admin')}>Admin</Button>
              <Button onClick={clearFilters}>Clear</Button>
            </div>
          </div>

          <Table hoverable className='shadow-md'>
            <Table.Head>
              <Table.HeadCell>#</Table.HeadCell>
              <Table.HeadCell>Date created</Table.HeadCell>
              <Table.HeadCell>User image</Table.HeadCell>
              <Table.HeadCell>Username</Table.HeadCell>
              <Table.HeadCell>Email</Table.HeadCell>
              <Table.HeadCell>Role</Table.HeadCell>
              <Table.HeadCell>Block</Table.HeadCell>
              <Table.HeadCell>Delete</Table.HeadCell>
              <Table.HeadCell>Details</Table.HeadCell>
            </Table.Head>
            <Table.Body className='divide-y'>
              {filteredUsers.map((user, index) => (
                <Table.Row className='bg-white dark:border-gray-700 dark:bg-gray-800' key={user._id}>
                  <Table.Cell>{index + 1}</Table.Cell>
                  <Table.Cell>{new Date(user.createdAt).toLocaleDateString()}</Table.Cell>
                  <Table.Cell>
                    <img
                      src={user.profilePicture}
                      alt={user.username}
                      className="w-10 h-10 rounded-full"
                    />
                  </Table.Cell>
                  <Table.Cell>{user.username}</Table.Cell>
                  <Table.Cell>{user.email}</Table.Cell>
                  <Table.Cell>
                    <Button
                      onClick={() => handleUpdateRole(user._id, user.role)}
                      color={user.role === 'admin' ? 'failure' : 'success'}
                    >
                      {user.role}
                    </Button>
                  </Table.Cell>
                  <Table.Cell>
                    <Button
                      onClick={() => handleBlockUnblockUser(user._id, user.isBlocked)}
                      color={user.isBlocked ? 'success' : 'failure'}
                    >
                      {user.isBlocked ? 'Unblock' : 'Block'}
                    </Button>
                  </Table.Cell>
                  <Table.Cell>
                    <Button
                      onClick={() => handleDeleteUser(user._id)}
                      color="failure"
                    >
                      Delete
                    </Button>
                  </Table.Cell>
                  <Table.Cell>
                    <Button
                      onClick={() => navigate(`/userdetails/${user._id}`)}
                      color="info"
                    >
                      View
                    </Button>
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>

          {showMore && (
            <div className="mt-4 flex justify-center">
              <Button onClick={handleShowMore}>Show More</Button>
            </div>
          )}
        </>
      ) : (
        <Alert color="info">
          No users found or you do not have access.
        </Alert>
      )}
    </div>
  );
}
