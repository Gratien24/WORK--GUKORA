import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'store.json');
const SESSION_SECRET = process.env.SESSION_SECRET || '';
if (process.env.RENDER === 'true' && SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be configured in production.');
}

async function loadStore(){
  await fs.mkdir(DATA_DIR,{recursive:true});
  try { return JSON.parse(await fs.readFile(DB_FILE,'utf8')); }
  catch { return {kv:{}}; }
}
let dbPromise = loadStore();
let writeQueue = Promise.resolve();
async function withDb(fn){
  const db = await dbPromise;
  return fn(db);
}
async function saveDb(db){
  writeQueue = writeQueue.then(async()=>{
    await fs.mkdir(DATA_DIR,{recursive:true});
    await fs.writeFile(DB_FILE, JSON.stringify(db), 'utf8');
  });
  return writeQueue;
}
const get = async key => withDb(db=>db.kv[key] ?? null);
const set = async (key,val) => { const db=await dbPromise; db.kv[key]=val; await saveDb(db); };
const del = async key => { const db=await dbPromise; delete db.kv[key]; await saveDb(db); };

const app=express();
app.set('trust proxy',1);
app.use(cookieParser());
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:false}));
app.use(express.static(__dirname, { index: 'index.html' }));

app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, message: 'WORK backend is online on Render.' });
});

function hashPassword(p){const s=crypto.randomBytes(16).toString('hex');return `${s}:${crypto.scryptSync(p,s,64).toString('hex')}`}
function verifyPassword(p,v){try{const [s,h]=String(v||'').split(':');if(!s||!h||h.length!==128)return false;const x=crypto.scryptSync(p,s,64).toString('hex');return crypto.timingSafeEqual(Buffer.from(x,'hex'),Buffer.from(h,'hex'))}catch{return false}}
function sign(d){const p=Buffer.from(JSON.stringify(d)).toString('base64url');const s=crypto.createHmac('sha256',SESSION_SECRET).update(p).digest('base64url');return p+'.'+s}
function verifySigned(raw){try{const [p,s]=String(raw||'').split('.');if(!p||!s)return null;const e=crypto.createHmac('sha256',SESSION_SECRET).update(p).digest('base64url');if(!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(e)))return null;const d=JSON.parse(Buffer.from(p,'base64url').toString());return d.exp>Date.now()?d:null}catch{return null}}
function session(req,name){return verifySigned(req.cookies?.[name]);}
function setCookie(res,name,data,maxAge){res.cookie(name,sign(data),{httpOnly:true,secure:reqSecure(res.req),sameSite:'lax',path:'/',maxAge});}
function reqSecure(req){return req.secure===true;}
function clearCookie(res,name){res.clearCookie(name,{httpOnly:true,secure:reqSecure(res.req),sameSite:'lax',path:'/'});}
function adminSess(req){const d=verifySigned(req.cookies?.work_admin);return d?.admin?d:null}
function userSess(req){return verifySigned(req.cookies?.work_session)}
function json(res,body,status=200){res.status(status).json(body)}
function referralCodeFor(id){return String(id||'').replace(/-/g,'').slice(0,8).toUpperCase() || crypto.randomBytes(4).toString('hex').toUpperCase()}
function cleanUser(u){return {id:u.id,name:u.name,phone:u.phone,email:u.email,balance:u.balance||0,investment:u.investment||0,profit:u.profit||0,referralCode:u.referralCode||referralCodeFor(u.id),referredBy:u.referredBy||null,inviteEarnings:u.inviteEarnings||0,inviteCount:u.inviteCount||0}}
async function user(id){return get(`user:${id}`)}
async function byEmail(e){const x=await get(`email:${e}`);return x?user(x.id):null}
async function tx(uid,type,amount){const t={id:crypto.randomUUID(),userId:uid,type,amount,status:'PENDING',created_at:new Date().toISOString()};await set(`tx:${t.id}`,t);const a=(await get(`txindex:${uid}`))||[];a.unshift(t.id);await set(`txindex:${uid}`,a.slice(0,100));const all=(await get('alltx'))||[];all.unshift(t.id);await set('alltx',all.slice(0,1000));return t}
async function txs(uid){const ids=(await get(`txindex:${uid}`))||[];const out=[];for(const id of ids){const t=await get(`tx:${id}`);if(t)out.push(t)}return out}

app.get('/api', async(req,res)=>handle(req,res));
app.post('/api', async(req,res)=>handle(req,res));
async function handle(req,res){
 try{
  const body=req.body||{};
  const action=String(req.query.action||body.action||'');
  if(action==='health') return json(res,{ok:true,message:'WORK backend is online on Render.'});
  if(action==='register'){
   const name=String(body.name||'').trim(), phone=String(body.phone||'').trim(), email=String(body.email||'').trim().toLowerCase(), password=String(body.password||'');
   if(!name||!phone||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8)return json(res,{ok:false,message:'Fill all fields. Password must be at least 8 characters.'},400);
   if(await byEmail(email))return json(res,{ok:false,message:'That email is already registered.'},409);
   const id=crypto.randomUUID(),ref=String(body.ref||'').trim().toUpperCase();
    let referrer=null;
    if(ref){const ids=(await get('allusers'))||[];for(const rid of ids){const candidate=await user(rid);if(candidate&&(candidate.referralCode||referralCodeFor(candidate.id))===ref){referrer=candidate;break}}}
    const u={id,name,phone,email,password_hash:hashPassword(password),balance:0,investment:0,profit:0,referralCode:referralCodeFor(id),referredBy:referrer?.id||null,inviteEarnings:0,inviteCount:0,created_at:new Date().toISOString()};
   await set(`user:${id}`,u);await set(`email:${email}`,{id});const users=(await get('allusers'))||[];users.unshift(id);await set('allusers',users.slice(0,1000));
   setCookie(res,'work_session',{userId:id,exp:Date.now()+604800000},604800000);return json(res,{ok:true,message:'Account created successfully.'});
  }
  if(action==='login'){
   const email=String(body.email||'').trim().toLowerCase(),password=String(body.password||''),u=await byEmail(email);
   if(!u||!verifyPassword(password,u.password_hash))return json(res,{ok:false,message:'Invalid email or password.'},401);
   setCookie(res,'work_session',{userId:u.id,exp:Date.now()+604800000},604800000);return json(res,{ok:true,message:'Login successful.'});
  }
  if(action==='admin_login'){
   const email=String(body.email||'').trim().toLowerCase(),password=String(body.password||'');
   if(!process.env.ADMIN_EMAIL||!process.env.ADMIN_PASSWORD)return json(res,{ok:false,message:'Admin access is not configured. Add ADMIN_EMAIL and ADMIN_PASSWORD in Render Environment Variables.'},503);
   if(String(process.env.ADMIN_PASSWORD).length < 12)return json(res,{ok:false,message:'ADMIN_PASSWORD must be at least 12 characters.'},503);
   if(email!==String(process.env.ADMIN_EMAIL).trim().toLowerCase()||password!==String(process.env.ADMIN_PASSWORD))return json(res,{ok:false,message:'Invalid admin credentials.'},401);
   setCookie(res,'work_admin',{admin:true,exp:Date.now()+3600000},3600000);return json(res,{ok:true,message:'Admin login successful.'});
  }
  if(action==='admin_logout'){clearCookie(res,'work_admin');return json(res,{ok:true,message:'Admin logged out.'})}
  if(action==='logout'){clearCookie(res,'work_session');return json(res,{ok:true,message:'Logged out.'})}
  if(action==='admin_payment_methods'){
   if(!adminSess(req))return json(res,{ok:false,message:'Admin login required.'},401);
   return json(res,{ok:true,methods:(await get('payment_methods'))||[]});
  }
  if(action==='admin_payment_method_save'){
   if(!adminSess(req))return json(res,{ok:false,message:'Admin login required.'},401);
   const name=String(body.name||'').trim(),account=String(body.account||'').trim(),holder=String(body.holder||'').trim(),instructions=String(body.instructions||'').trim();
   if(!name||!account||!holder)return json(res,{ok:false,message:'Name, account/number and account name are required.'},400);
   const methods=(await get('payment_methods'))||[]; const id=String(body.id||crypto.randomUUID()); const item={id,name,account,holder,instructions,enabled:body.enabled!==false,updated_at:new Date().toISOString()}; const i=methods.findIndex(x=>x.id===id); if(i>=0)methods[i]=item; else methods.unshift(item); await set('payment_methods',methods.slice(0,50)); return json(res,{ok:true,message:'Payment method saved.'});
  }
  if(action==='admin_payment_method_delete'){
   if(!adminSess(req))return json(res,{ok:false,message:'Admin login required.'},401);
   const id=String(body.id||''); const methods=((await get('payment_methods'))||[]).filter(x=>x.id!==id); await set('payment_methods',methods); return json(res,{ok:true,message:'Payment method deleted.'});
  }
  if(action==='payment_methods')return json(res,{ok:true,methods:((await get('payment_methods'))||[]).filter(x=>x.enabled!==false)});
  if(action==='admin_invite_settings'){
    if(!adminSess(req))return json(res,{ok:false,message:'Admin login required.'},401);
    const percentage=Number(await get('invite_percentage'));return json(res,{ok:true,percentage:Number.isFinite(percentage)&&percentage>=0?percentage:5});
  }
  if(action==='admin_invite_settings_save'){
    if(!adminSess(req))return json(res,{ok:false,message:'Admin login required.'},401);
    const percentage=Number(body.percentage);if(!Number.isFinite(percentage)||percentage<0||percentage>100)return json(res,{ok:false,message:'Percentage must be between 0 and 100.'},400);
    await set('invite_percentage',percentage);return json(res,{ok:true,message:'Invite percentage saved.',percentage});
  }
  if(action==='admin_dashboard'){
   if(!adminSess(req))return json(res,{ok:false,message:'Admin login required.'},401);
   const ids=(await get('allusers'))||[],users=[];for(const id of ids){const x=await user(id);if(x)users.push(cleanUser(x))}
   const tids=(await get('alltx'))||[],transactions=[];for(const id of tids){const x=await get(`tx:${id}`);if(x)transactions.push(x)}
   return json(res,{ok:true,users,transactions});
  }
  if(action==='admin_tx_action'){
   if(!adminSess(req))return json(res,{ok:false,message:'Admin login required.'},401);
   const id=String(body.id||''),decision=String(body.decision||'').toUpperCase();if(!id||!['APPROVE','REJECT'].includes(decision))return json(res,{ok:false,message:'Invalid transaction action.'},400);
   const t=await get(`tx:${id}`);if(!t)return json(res,{ok:false,message:'Transaction not found.'},404);if(t.status!=='PENDING')return json(res,{ok:false,message:`Transaction is already ${t.status}.`},409);
   const target=await user(t.userId);if(!target)return json(res,{ok:false,message:'User account not found.'},404);
   if(decision==='REJECT'){t.status='REJECTED';t.reviewed_at=new Date().toISOString();t.reviewed_by='ADMIN';await set(`tx:${t.id}`,t);return json(res,{ok:true,message:'Transaction rejected.'})}
   const amount=Math.floor(Number(t.amount||0));if(!Number.isFinite(amount)||amount<=0)return json(res,{ok:false,message:'Invalid transaction amount.'},400);
   if(t.type==='DEPOSIT')target.balance=(target.balance||0)+amount;
   else if(t.type==='WITHDRAWAL'){if(amount>(target.balance||0))return json(res,{ok:false,message:'User no longer has enough available balance.'},400);target.balance=(target.balance||0)-amount}
   else if(t.type==='INVESTMENT'){
      target.investment=(target.investment||0)+amount;
      if(target.referredBy){const referrer=await user(target.referredBy);if(referrer){const pctRaw=Number(await get('invite_percentage'));const pct=Number.isFinite(pctRaw)&&pctRaw>=0?pctRaw:5;const commission=Math.floor(amount*pct/100);if(commission>0){referrer.balance=(referrer.balance||0)+commission;referrer.inviteEarnings=(referrer.inviteEarnings||0)+commission;referrer.inviteCount=(referrer.inviteCount||0)+1;await set(`user:${referrer.id}`,referrer);}}}
    }
   else return json(res,{ok:false,message:'Unsupported transaction type.'},400);
   await set(`user:${target.id}`,target);t.status='APPROVED';t.reviewed_at=new Date().toISOString();t.reviewed_by='ADMIN';await set(`tx:${t.id}`,t);return json(res,{ok:true,message:'Transaction approved.'});
  }
  if(action==='forgot_password')return json(res,{ok:true,message:'Request received. Please contact WORK Support on WhatsApp to complete your password reset.'});
  if(action==='reset_password')return json(res,{ok:false,message:'Password reset links require an email provider configuration.'},503);
  const s=userSess(req);if(!s)return json(res,{ok:false,message:'Please login first.'},401);const u=await user(s.userId);if(!u)return json(res,{ok:false,message:'Account not found.'},404);
  if(action==='dashboard')return json(res,{ok:true,user:cleanUser(u),transactions:(await txs(u.id)).slice(0,10)});
  if(action==='invite'){
    const ids=(await get('allusers'))||[],invitees=[];for(const id of ids){const x=await user(id);if(x&&x.referredBy===u.id)invitees.push({name:x.name,email:x.email,created_at:x.created_at});}
    const pctRaw=Number(await get('invite_percentage'));const percentage=Number.isFinite(pctRaw)&&pctRaw>=0?pctRaw:5;return json(res,{ok:true,referralCode:u.referralCode||referralCodeFor(u.id),inviteEarnings:u.inviteEarnings||0,inviteCount:invitees.length,percentage,invitees});
  }
  if(action==='transactions')return json(res,{ok:true,rows:await txs(u.id)});
  if(action==='profile')return json(res,{ok:true,user:cleanUser(u)});
  if(action==='deposit'){const a=Math.floor(Number(body.amount||0));if(a<3000)return json(res,{ok:false,message:'Minimum deposit is 3,000 Frw.'},400);const pm=String(body.paymentMethodId||'');const methods=((await get('payment_methods'))||[]).filter(x=>x.enabled!==false);if(pm&&!methods.some(x=>x.id===pm))return json(res,{ok:false,message:'Selected payment method is unavailable.'},400);const t=await tx(u.id,'DEPOSIT',a);t.paymentMethodId=pm;t.reference=String(body.reference||'').trim();await set(`tx:${t.id}`,t);return json(res,{ok:true,message:'Deposit request recorded as PENDING. No real payment was processed.'})}
  if(action==='withdraw'){const a=Math.floor(Number(body.amount||0));if(a<3000)return json(res,{ok:false,message:'Minimum withdrawal is 3,000 Frw.'},400);if(a>(u.balance||0))return json(res,{ok:false,message:'Insufficient available balance.'},400);await tx(u.id,'WITHDRAWAL',a);return json(res,{ok:true,message:'Withdrawal request recorded as PENDING.'})}
  if(action==='investment_request'){const a=Math.floor(Number(body.amount||0));const pm=String(body.paymentMethodId||'');const ref=String(body.reference||'').trim();if(a<3000)return json(res,{ok:false,message:'Minimum investment is 3,000 Frw.'},400);const methods=((await get('payment_methods'))||[]).filter(x=>x.enabled!==false);const method=methods.find(x=>x.id===pm);if(!method)return json(res,{ok:false,message:'Please select an available payment method.'},400);if(!ref)return json(res,{ok:false,message:'Enter the payment/reference number after payment.'},400);const t=await tx(u.id,'INVESTMENT',a);t.paymentMethodId=pm;t.paymentMethod=method.name;t.reference=ref;await set(`tx:${t.id}`,t);return json(res,{ok:true,message:'Investment payment submitted as PENDING. Admin will verify the payment before activation.'})}
  return json(res,{ok:false,message:'Unknown action.'},404);
 }catch(e){console.error(e);return json(res,{ok:false,message:'Server error. Check Render logs.'},500)}
}

const PORT=Number(process.env.PORT||10000);
app.listen(PORT,'0.0.0.0',()=>console.log(`WORK GUKORA listening on ${PORT}`));
