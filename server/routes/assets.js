import { Router } from 'express';
import { store } from '../data/store.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();
router.use(authenticate);

router.get('/', (req, res) => {
  res.json({ data: store.assets, total: store.assets.length, simulation: true });
});

router.get('/identities', (req, res) => {
  res.json({ data: store.identities, total: store.identities.length, simulation: true });
});

router.get('/credentials', (req, res) => {
  res.json({ data: store.credentials, total: store.credentials.length, simulation: true });
});

router.get('/policies', (req, res) => {
  res.json({ data: store.policies, total: store.policies.length, simulation: true });
});

export default router;
