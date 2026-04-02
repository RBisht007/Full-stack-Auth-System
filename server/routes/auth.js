import express from 'express';
import {
  register,
  login,
  logout,
  refresh,
  enable2FA,
  resetPassword,
  verifyEmail,
} from '../controllers/authController.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.post('/refresh', refresh);
router.get('/verify-email', verifyEmail);
router.post('/enable-2fa', authenticate, enable2FA);
router.post('/reset-password', resetPassword);
router.get('/profile', authenticate, (req, res) => {
  res.json({ user: req.user });
});

export default router;