import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { chat, analyzeAlert, analystStatus } from '../services/grokAnalyst.js';
import { addAudit } from '../data/store.js';

const router = Router();
router.use(authenticate);

const chatSchema = z.object({
  body: z.object({
    message: z.string().min(1).max(2000),
    history: z.array(z.object({
      role: z.enum(['user', 'assistant']),
      content: z.string()
    })).max(20).optional()
  })
});

router.post('/chat', validate(chatSchema), async (req, res) => {
  try {
    const result = await chat(req.body.message, req.body.history || []);
    addAudit(req.user.name, 'ai.chat', result.live ? 'grok-live' : 'grok-analyst', 'success', req.body.message.slice(0, 80));
    res.json(result);
  } catch {
    res.status(500).json({ error: 'Analyst request failed' });
  }
});

router.get('/analyze/alert/:id', (req, res) => {
  const result = analyzeAlert(req.params.id);
  if (result.error) return res.status(404).json(result);
  addAudit(req.user.name, 'ai.analyze', req.params.id, 'success');
  res.json(result);
});

router.get('/status', (_req, res) => {
  res.json(analystStatus());
});

export default router;
