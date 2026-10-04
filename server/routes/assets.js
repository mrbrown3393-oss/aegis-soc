import { Router } from 'express';
import { store } from '../data/store.js';
import { authenticate, scoped } from '../middleware/auth.js';
const router=Router(); router.use(authenticate);
router.get('/',(req,res)=>{const data=scoped(store.assets,req.user);res.json({data,total:data.length,simulation:true});});
router.get('/identities',(req,res)=>{const data=scoped(store.identities,req.user);res.json({data,total:data.length,simulation:true});});
router.get('/credentials',(req,res)=>{const data=scoped(store.credentials,req.user);res.json({data,total:data.length,simulation:true});});
router.get('/policies',(req,res)=>{const data=scoped(store.policies,req.user);res.json({data,total:data.length,simulation:true});});
export default router;