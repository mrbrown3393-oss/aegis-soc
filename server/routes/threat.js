import { Router } from 'express';
import { store } from '../data/store.js';
import { authenticate, scoped } from '../middleware/auth.js';
const router=Router(); router.use(authenticate);
router.get('/intel',(req,res)=>{const data=scoped(store.threatIntel,req.user);res.json({data,total:data.length,simulation:true});});
router.get('/events',(req,res)=>{const limit=Math.min(parseInt(req.query.limit)||50,200);const data=scoped(store.events,req.user).slice(-limit).reverse();res.json({data,total:data.length,simulation:true});});
router.get('/audit',(req,res)=>{const limit=Math.min(parseInt(req.query.limit)||50,200);const data=scoped(store.auditLog,req.user).slice(0,limit);res.json({data,total:data.length,simulation:true});});
export default router;