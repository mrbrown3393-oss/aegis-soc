import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { config } from '../config.js';
import { store, addAudit } from '../data/store.js';
import { validate } from '../middleware/validate.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();

const loginSchema = z.object({
  body: z.object({
    email: z.string().email(),
    password: z.string().min(8)
  })
});

router.post('/login', validate(loginSchema), async (req, res) => {
  const { email, password } = req.body;
  const user = store.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    addAudit(email, 'user.login', 'auth', 'denied', 'Invalid credentials');
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const token = jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    config.JWT_SECRET,
    { expiresIn: config.JWT_EXPIRES_IN }
  );
  user.lastLogin = new Date().toISOString();
  addAudit(user.name, 'user.login', 'auth', 'success');
  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      department: user.department,
      mfaEnabled: user.mfaEnabled
    },
    simulation: true
  });
});

router.get('/me', authenticate, (req, res) => {
  const user = store.users.find(u => u.id === req.user.id);
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    department: user.department,
    mfaEnabled: user.mfaEnabled,
    lastLogin: user.lastLogin
  });
});

router.post('/logout', authenticate, (req, res) => {
  addAudit(req.user.name, 'user.logout', 'auth', 'success');
  res.json({ ok: true });
});

export default router;
