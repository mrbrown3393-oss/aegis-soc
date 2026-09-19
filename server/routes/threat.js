import { Router } from 'express';
import { store } from '../data/store.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();
router.use(authenticate);

router.get('/intel', (req, res) => {
  res.json({ data: store.threatIntel, total: store.threatIntel.length, simulation: true });
});

router.get('/events', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const events = store.events.slice(-limit).reverse();
  res.json({ data: events, total: events.length, simulation: true });
});

router.get('/audit', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  res.json({ data: store.auditLog.slice(0, limit), total: store.auditLog.length, simulation: true });
});

export default router;
