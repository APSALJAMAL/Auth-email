import { Alert, Button, Modal, TextInput, Label, Select } from 'flowbite-react';
import { useEffect, useRef, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import {
  getDownloadURL,
  getStorage,
  ref,
  uploadBytesResumable,
} from 'firebase/storage';
import { app } from '../redux/firebase';
import { CircularProgressbar } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';
import {
  updateStart,
  updateSuccess,
  updateFailure,
  deleteUserStart,
  deleteUserSuccess,
  deleteUserFailure,
  signoutSuccess,
} from '../redux/user/userSlice';
import { HiOutlineExclamationCircle } from 'react-icons/hi';
import { Link } from 'react-router-dom';

export default function UserDetails() {
  const { currentUser, error, loading } = useSelector((state) => state.user);
  const [imageFile, setImageFile] = useState(null);
  const [imageFileUrl, setImageFileUrl] = useState(null);
  const [imageFileUploadProgress, setImageFileUploadProgress] = useState(null);
  const [imageFileUploadError, setImageFileUploadError] = useState(null);
  const [imageFileUploading, setImageFileUploading] = useState(false);
  const [updateUserSuccess, setUpdateUserSuccess] = useState(null);
  const [updateUserError, setUpdateUserError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({});
  const filePickerRef = useRef();
  const dispatch = useDispatch();
  
  const [role, setRole] = useState(currentUser.role);
  const [isBlocked, setIsBlocked] = useState(currentUser.isBlocked);

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImageFile(file);
      setImageFileUrl(URL.createObjectURL(file));
    }
  };

  useEffect(() => {
    if (imageFile) {
      uploadImage();
    }
  }, [imageFile]);

  const uploadImage = async () => {
    setImageFileUploading(true);
    setImageFileUploadError(null);
    const storage = getStorage(app);
    const fileName = new Date().getTime() + imageFile.name;
    const storageRef = ref(storage, fileName);
    const uploadTask = uploadBytesResumable(storageRef, imageFile);
    uploadTask.on(
      'state_changed',
      (snapshot) => {
        const progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
        setImageFileUploadProgress(progress.toFixed(0));
      },
      (error) => {
        setImageFileUploadError('Could not upload image (File must be less than 2MB)');
        setImageFileUploadProgress(null);
        setImageFile(null);
        setImageFileUrl(null);
        setImageFileUploading(false);
      },
      () => {
        getDownloadURL(uploadTask.snapshot.ref).then((downloadURL) => {
          setImageFileUrl(downloadURL);
          setFormData({ ...formData, profilePicture: downloadURL });
          setImageFileUploading(false);
        });
      }
    );
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.id]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setUpdateUserError(null);
    setUpdateUserSuccess(null);
    if (Object.keys(formData).length === 0 && !role && !isBlocked) {
      setUpdateUserError('No changes made');
      return;
    }
    if (imageFileUploading) {
      setUpdateUserError('Please wait for image to upload');
      return;
    }
    try {
      dispatch(updateStart());
      const res = await fetch(`/api/user/update/${currentUser._id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...formData,
          role,
          isBlocked,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        dispatch(updateFailure(data.message));
        setUpdateUserError(data.message);
      } else {
        dispatch(updateSuccess(data));
        setUpdateUserSuccess("User's profile updated successfully");
      }
    } catch (error) {
      dispatch(updateFailure(error.message));
      setUpdateUserError(error.message);
    }
  };

  const handleDeleteUser = async () => {
    setShowModal(false);
    try {
      dispatch(deleteUserStart());
      const res = await fetch(`/api/user/delete/${currentUser._id}`, {
        method: 'DELETE',
      });
      const data = await res.json();
      if (!res.ok) {
        dispatch(deleteUserFailure(data.message));
      } else {
        dispatch(deleteUserSuccess(data));
      }
    } catch (error) {
      dispatch(deleteUserFailure(error.message));
    }
  };

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

  return (
    <div className="max-w-6xl mx-auto p-3 w-full">
      <h1 className="my-7 text-center font-semibold text-3xl">Profile</h1>
      <div className="flex gap-6">
        {/* Left div: User profile */}
        <div className="flex-shrink-0 w-1/3 flex justify-center items-center flex-col">
  <div
    className="relative w-64 h-64 cursor-pointer shadow-md overflow-hidden rounded-full"
    onClick={() => filePickerRef.current.click()}
  >
    {imageFileUploadProgress && (
      <CircularProgressbar
        value={imageFileUploadProgress || 0}
        text={`${imageFileUploadProgress}%`}
        strokeWidth={5}
        styles={{
          root: {
            width: '100%',
            height: '100%',
            position: 'absolute',
            top: 0,
            left: 0,
          },
          path: {
            stroke: `rgba(60, 179, 113, ${imageFileUploadProgress / 100})`,
          },
          text: {
            fill: 'green',
          },
        }}
      />
    )}

    <img
      src={imageFileUrl || currentUser.profilePicture}
      alt="user"
      className={`rounded-full w-full h-full object-cover border-8 border-[lightgray] ${imageFileUploadProgress && imageFileUploadProgress < 100 && 'opacity-90'}`}
    />
  </div>
  <p className="font-semibold text-center text-sm mt-3">Click the Profile to change</p>
</div>

        
        {/* Right div: Form and other details */}
        <div className="w-2/3">
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <input
              type="file"
              accept="image/*"
              onChange={handleImageChange}
              ref={filePickerRef}
              hidden
            />
            {imageFileUploadError && <Alert color="failure">{imageFileUploadError}</Alert>}

            <Label value="Your email" />
            <TextInput
              type="email"
              id="email"
              placeholder="email"
              defaultValue={currentUser.email}
              onChange={handleChange}
              readOnly
            />
            <Label value="Change Username" />
            <TextInput
              type="text"
              id="username"
              placeholder="username"
              defaultValue={currentUser.username}
              onChange={handleChange}
            />
            <Label value="Change password" />
            <TextInput
              type="password"
              id="password"
              placeholder="password"
              onChange={handleChange}
            />
            <Label value="User Role" />
            <Select
              id="role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              <option value="user">User</option>
              <option value="admin">Admin</option>
              
            </Select>
            <Label value="Block User" />
            <Select
              id="isBlocked"
              value={isBlocked ? 'true' : 'false'}
              onChange={(e) => setIsBlocked(e.target.value === 'true')}
            >
              <option value="false">Unblocked</option>
              <option value="true">Blocked</option>
            </Select>
            <Button
              type="submit"
              gradientDuoTone="purpleToBlue"
              outline
              disabled={loading || imageFileUploading}
            >
              {loading ? 'Loading...' : 'Update'}
            </Button>
            {currentUser.isAdmin && (
              <Link to={'/create-post'}>
                <Button type="button" gradientDuoTone="purpleToPink" className="w-full">
                  Create a post
                </Button>
              </Link>
            )}
          </form>

          <div className="text-red-500 flex justify-between mt-5 pb-4">
            <span onClick={() => setShowModal(true)} className="cursor-pointer">Delete Account</span>
            <span onClick={handleSignout} className="cursor-pointer">Sign Out</span>
          </div>

          {updateUserSuccess && (
            <Alert color="success" className="mt-5">
              {updateUserSuccess}
            </Alert>
          )}
          {updateUserError && (
            <Alert color="failure" className="mt-5">
              {updateUserError}
            </Alert>
          )}
          {error && (
            <Alert color="failure" className="mt-5">
              {error}
            </Alert>
          )}

          <Modal show={showModal} onClose={() => setShowModal(false)}>
            <Modal.Header>Delete Account</Modal.Header>
            <Modal.Body>
              <p>Are you sure you want to delete your account? This action is irreversible.</p>
            </Modal.Body>
            <Modal.Footer>
              <Button color="failure" onClick={handleDeleteUser}>Delete</Button>
              <Button onClick={() => setShowModal(false)}>Cancel</Button>
            </Modal.Footer>
          </Modal>
        </div>
      </div>
    </div>
  );
}
