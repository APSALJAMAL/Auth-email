import express from 'express';
import {
  deleteUser,
  getUser,
  getUsers,
  signout,
  updateUser,
  updateRole,
  blockUser,
  unblockUser,
} from '../controllers/user.controller.js';
import { verifyToken } from '../utils/verifyUser.js';

const router = express.Router();


router.put('/update/:userId', verifyToken, updateUser);
router.delete('/delete/:userId',  deleteUser);
router.post('/signout',verifyToken, signout);
router.get('/getusers', getUsers);
router.patch('/updateRole/:userId', updateRole);
router.patch('/block/:userId', blockUser);
router.patch('/unblock/:userId', unblockUser);
router.get('/getuser/:userId', getUser);



export default router;