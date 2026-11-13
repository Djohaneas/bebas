import fs from "fs/promises";import path from "path";import crypto from "crypto";
const dir=process.env.DATA_DIR||path.join(process.cwd(),"data"),file=path.join(dir,"db.json");let chain=Promise.resolve();
async function read(){try{return JSON.parse(await fs.readFile(file,"utf8"))}catch{return {messages:[]}}}
export const load=()=>chain.then(read);
export function tx(fn){const r=chain.then(async()=>{const db=await read(),out=await fn(db);await fs.mkdir(dir,{recursive:true});await fs.writeFile(file+".tmp",JSON.stringify(db));await fs.rename(file+".tmp",file);return out});chain=r.catch(()=>{});return r}
export const validId=id=>/^[a-f0-9]{12}$/.test(id);
const upDir=()=>path.join(dir,"uploads"),upFile=id=>path.join(upDir(),id+".jpg");
export async function savePhoto(id,buf){await fs.mkdir(upDir(),{recursive:true});await fs.writeFile(upFile(id),buf)}
export const readPhoto=id=>validId(id)?fs.readFile(upFile(id)).catch(()=>null):null;
export const rmPhoto=id=>validId(id)?fs.rm(upFile(id),{force:true}):null;
export const newId=()=>crypto.randomBytes(6).toString("hex");
const hits=new Map();
export const clientIp=req=>(req.headers.get("x-forwarded-for")||req.headers.get("x-real-ip")||"local").split(",")[0].trim();
export function limited(req,max=10){const ip=clientIp(req),n=Date.now(),a=(hits.get(ip)||[]).filter(t=>n-t<60000);a.push(n);hits.set(ip,a);
if(hits.size>5000)for(const [k,v] of hits)if(!v.some(t=>n-t<60000))hits.delete(k);return a.length>max}
export const hashIp=req=>crypto.createHash("sha256").update(clientIp(req)+(process.env.ADMIN_KEY||"")).digest("hex").slice(0,16);
export const REPORT_LIMIT=+process.env.REPORT_LIMIT||3;
export const AUTO_DELETE_LIMIT=+process.env.AUTO_DELETE_LIMIT||15;
export const isAdmin=req=>{const k=process.env.ADMIN_KEY;return !!k&&req.headers.get("x-admin-key")===k};
export const publicView=({reporters,...m},admin=false)=>({...m,replies:(m.replies||[]).filter(r=>admin||!r.deleted).map(({reporters:_r,...r})=>r)});
export const clean=(s,m)=>String(s??"").replace(/\s+/g," ").trim().slice(0,m);

const sgDir=()=>path.join(dir,"songs"),sgFile=id=>path.join(sgDir(),id+".mp3");
export async function saveSong(id,buf){await fs.mkdir(sgDir(),{recursive:true});await fs.writeFile(sgFile(id),buf)}
export const readSong=id=>validId(id)?fs.readFile(sgFile(id)).catch(()=>null):null;
export const rmSong=id=>validId(id)?fs.rm(sgFile(id),{force:true}):null;

export const rmStatic=name=>fs.rm(path.join(process.cwd(),"public","songs",name+".mp3"),{force:true}).catch(()=>{});

// ===== Pengawas: perangkat, aktivitas, blokir (disimpan di data/monitor.json) =====
const mFile=()=>path.join(dir,"monitor.json");
export function mload(){const g=globalThis;g.__wbMonP=g.__wbMonP||(async()=>{let o={};try{o=JSON.parse(await fs.readFile(mFile(),"utf8"))}catch{}return {devices:{},activity:[],blocks:[],...o}})();return g.__wbMonP}
async function mflush(now){const g=globalThis,run=async()=>{g.__wbT=null;try{const m=await mload();await fs.mkdir(dir,{recursive:true});await fs.writeFile(mFile()+".tmp",JSON.stringify(m));await fs.rename(mFile()+".tmp",mFile())}catch{}};
if(now){if(g.__wbT)clearTimeout(g.__wbT);return run()}if(!g.__wbT)g.__wbT=setTimeout(run,4000)}
export async function mutate(fn,now){const m=await mload(),out=fn(m);await mflush(now);return out}
export const didOf=req=>{const m=/(?:^|;\s*)wb_did=([a-f0-9]{16,32})/.exec(req.headers.get("cookie")||"");return m?m[1]:"ip-"+hashIp(req)};
const pres=()=>globalThis.__wbPres||(globalThis.__wbPres=new Map());
export const presence=pres;
export function ping(did,p){const m=pres(),o=m.get(did),n=Date.now();m.set(did,{t:n,path:p||o?.path});if(m.size>5000)for(const [k,v] of m)if(n-v.t>600000)m.delete(k)}
export async function guard(req){if(isAdmin(req))return false;const m=await mload(),did=didOf(req),ip=clientIp(req);return m.blocks.some(b=>b.kind==="device"?b.value===did:b.value===ip)}
export const blockedRes=()=>new Response(JSON.stringify({error:"Akses diblokir oleh admin."}),{status:403,headers:{"content-type":"application/json"}});
export async function track(req,type,detail="",p){const did=didOf(req),ip=clientIp(req),ua=(req.headers.get("user-agent")||"").slice(0,200),n=Date.now();ping(did,p);
try{await mutate(m=>{const d=m.devices[did]=m.devices[did]||{id:did,first:n,hits:0,ips:[]};d.last=n;d.hits++;d.ua=ua;d.ip=ip;d.path=p||d.path;if(!d.ips.includes(ip)){d.ips.push(ip);if(d.ips.length>5)d.ips.shift()}
const ks=Object.keys(m.devices);if(ks.length>1000){ks.sort((a,b)=>m.devices[a].last-m.devices[b].last);ks.slice(0,ks.length-1000).forEach(k=>delete m.devices[k])}
m.activity.push({t:n,did,ip,type,detail:String(detail).slice(0,120)});if(m.activity.length>1500)m.activity.splice(0,m.activity.length-1500)})}catch{}}
