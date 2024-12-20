import { useEffect, useState } from 'react';
import { useSelector } from 'react-redux';
import { HiOutlineUserGroup, HiArrowNarrowUp } from 'react-icons/hi';
import { Button, Table } from 'flowbite-react';
import { Link } from 'react-router-dom';

export default function DashboardComp() {
  const [users, setUsers] = useState([]);
  const [totalUsers, setTotalUsers] = useState(0);
  const [lastMonthUsers, setLastMonthUsers] = useState(0);
  const [loading, setLoading] = useState(true); // Loading state
  const { currentUser } = useSelector((state) => state.user);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        setLoading(true); // Start loading
        const res = await fetch('/api/user/getusers?limit=5');
        if (!res.ok) throw new Error('Failed to fetch users');
        const data = await res.json();

        setUsers(data.users || []);
        setTotalUsers(data.totalUsers || 0);
        setLastMonthUsers(data.lastMonthUsers || 0);
      } catch (error) {
        console.error('Error fetching users:', error.message);
      } finally {
        setLoading(false); // Stop loading
      }
    };

    fetchUsers();
  }, [currentUser]);

  return (
    <div className="p-3 md:mx-auto">
      {/* User Stats Section */}
      <div className="flex flex-wrap gap-4 justify-center">
        {/* Total Users Card */}
        <div className="flex flex-col p-3 dark:bg-gray-800 gap-4 md:w-72 w-full rounded-md shadow-gray-800 shadow-xl dark:shadow-purple-500 dark:shadow-xl">
          <div className="flex justify-between">
            <div>
              <h3 className="text-gray-500 text-md uppercase">Total Users</h3>
              <p className="text-2xl">{totalUsers}</p>
            </div>
            <HiOutlineUserGroup className="bg-teal-600 text-white rounded-full text-5xl p-3 shadow-lg" />
          </div>
        </div>

        {/* Last Month Users Card */}
        <div className="flex flex-col p-3 dark:bg-gray-800 gap-4 md:w-72 w-full rounded-md shadow-gray-800 shadow-xl dark:shadow-purple-500 dark:shadow-xl">
          <div className="flex justify-between">
            <div>
              <h3 className="text-gray-500 text-md uppercase">Users Last Month</h3>
              <p className="text-2xl">{lastMonthUsers}</p>
            </div>
            <HiArrowNarrowUp className="bg-green-600 text-white rounded-full text-5xl p-3 shadow-lg" />
          </div>
        </div>
      </div>

      {/* Recent Users Section */}
      <div className="flex flex-wrap gap-4 py-3 mx-auto justify-center">
        <div className="flex flex-col w-full md:w-auto p-2 rounded-md dark:bg-gray-800 shadow-gray-800 shadow-xl dark:shadow-purple-500 dark:shadow-xl">
          <div className="flex justify-between p-3 text-sm font-semibold">
            <h1 className="text-center p-2">Recent Users</h1>
            <Button outline gradientDuoTone="purpleToPink">
              <Link to="/dashboard?tab=users" className="w-full">
                See all
              </Link>
            </Button>
          </div>
          {loading ? (
            <div className="text-center py-4 text-gray-500">Loading...</div>
          ) : (
            <Table hoverable>
              <Table.Head>
                <Table.HeadCell>Date Created</Table.HeadCell>
                <Table.HeadCell>User Image</Table.HeadCell>
                <Table.HeadCell>Username</Table.HeadCell>
                <Table.HeadCell>Email</Table.HeadCell>
              </Table.Head>
              <Table.Body className="divide-y">
                {users.length > 0 ? (
                  users.map((user) => (
                    <Table.Row
                      key={user._id}
                      className="bg-white dark:border-gray-700 dark:bg-gray-800"
                    >
                      <Table.Cell>{new Date(user.createdAt).toLocaleDateString()}</Table.Cell>
                      <Table.Cell>
                        <img
                          src={user.profilePicture || '/default-profile.png'}
                          alt="user"
                          className="w-10 h-10 rounded-full bg-gray-500"
                        />
                      </Table.Cell>
                      <Table.Cell>{user.username || 'N/A'}</Table.Cell>
                      <Table.Cell>{user.email || 'N/A'}</Table.Cell>
                    </Table.Row>
                  ))
                ) : (
                  <Table.Row>
                    <Table.Cell colSpan="4" className="text-center text-gray-500">
                      No users found
                    </Table.Cell>
                  </Table.Row>
                )}
              </Table.Body>
            </Table>
          )}
        </div>
      </div>
    </div>
  );
}
