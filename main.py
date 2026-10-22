import os,re,sqlite3
from datetime import datetime,timezone
from fastapi import FastAPI,Request,Form,Header,HTTPException
from fastapi.responses import HTMLResponse,JSONResponse,PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
DB_PATH=os.getenv("DB_PATH","/tmp/honeypot.db"); ADMIN_TOKEN=os.getenv("ADMIN_TOKEN","")
app=FastAPI(title="AI-Powered Honeypot System")
def db():
 c=sqlite3.connect(DB_PATH,timeout=10); c.row_factory=sqlite3.Row; return c
with db() as c:
 c.execute("""CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts TEXT,ip TEXT,method TEXT,path TEXT,ua TEXT,kind TEXT,severity TEXT,intent TEXT,blocked INTEGER)""")
def classify(path,payload,method):
 s=(path+" "+payload).lower()
 rules=[(r"union\s+select|select.+from|or\s+1=1|sqlmap","SQL Injection","HIGH","Database probing"),(r"<script|javascript:|onerror\s*=","XSS Probe","HIGH","Script injection"),(r"\.\./|/etc/passwd|win\.ini","Path Traversal","HIGH","File access probing"),(r"cmd=|/bin/sh|powershell|wget\s|curl\s","Command Injection / RCE Probe","CRITICAL","Command execution probing"),(r"/\.env|backup\.sql|/api/config|/phpmyadmin","Sensitive Resource Reconnaissance","MEDIUM","Searching for exposed resources"),(r"/admin|login|password","Login Probe","MEDIUM","Authentication probing")]
 for p,k,v,i in rules:
  if re.search(p,s): return k,v,i
 return ("Suspicious Request","LOW","Unusual request") if method in ("POST","PUT","DELETE") else ("General Scan","INFO","Routine browsing or automated probing")
def require(token):
 if not ADMIN_TOKEN: raise HTTPException(503,"Set ADMIN_TOKEN in Railway Variables first.")
 if token!=ADMIN_TOKEN: raise HTTPException(401,"Invalid admin token")
class Capture(BaseHTTPMiddleware):
 async def dispatch(self,request,call_next):
  path=request.url.path
  if path.startswith("/api/") or path=="/health": return await call_next(request)
  try: body=(await request.body())[:500].decode(errors="replace")
  except: body=""
  if path in ("/login","/admin"): body="[form values redacted; credentials are never stored]"
  kind,sev,intent=classify(path+"?"+request.url.query,body,request.method)
  blocked=bool(app.state.firewall and sev in ("MEDIUM","HIGH","CRITICAL"))
  with db() as c:
   c.execute("INSERT INTO events(ts,ip,method,path,ua,kind,severity,intent,blocked) VALUES(?,?,?,?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),request.client.host if request.client else "unknown",request.method,path,request.headers.get("user-agent","")[:200],kind,sev,intent,int(blocked)))
  if blocked: return PlainTextResponse("403 Forbidden — blocked by honeypot lab firewall",status_code=403)
  return await call_next(request)
app.state.firewall=True
app.add_middleware(Capture)
@app.get("/health")
def health(): return {"status":"ok"}
@app.get("/",response_class=HTMLResponse)
def home(): return HTMLResponse("""<html><head><meta name=viewport content="width=device-width"><link rel=stylesheet href=/static/style.css></head><body><nav><b>SwiftCargo Logistics</b><span>Track · Ship · Deliver</span></nav><main><small>LOGISTICS, MADE SIMPLE</small><h1>Moving your business forward.</h1><p>Reliable shipping and supply-chain services for modern businesses.</p><a href=/client-login>Client portal</a> · <a href=/track>Track shipment</a></main><section><h2>Shipment visibility</h2><p>Educational decoy site for cybersecurity demonstrations. Do not enter real credentials.</p><a href=/dashboard>Security dashboard</a></section></body></html>""")
@app.get("/client-login",response_class=HTMLResponse)
def login_page(): return HTMLResponse("<h1>Client Portal (Demo)</h1><p>Do not enter real credentials. Submitted values are not stored.</p><form method=post action=/login><input name=username placeholder='Demo username'><input name=password type=password placeholder='Demo password'><button>Submit demo</button></form>")
@app.post("/login")
def login(username:str=Form(default=""),password:str=Form(default="")): return HTMLResponse("<h2>Demo received</h2><p>Credentials are not stored.</p><a href=/>Home</a>")
@app.get("/track",response_class=HTMLResponse)
def track(): return HTMLResponse("<h2>Shipment tracking demo</h2><p>No real shipment data connected.</p>")
@app.get("/.env")
def env(): return JSONResponse({"message":"Decoy only; no secrets stored."})
@app.get("/backup.sql")
def backup(): return PlainTextResponse("-- Decoy only; no production data.")
@app.get("/api/config")
def config(): return {"environment":"honeypot-demo","credentials":"not-present"}
@app.get("/admin",response_class=HTMLResponse)
def admin(): return HTMLResponse("<h2>Admin decoy</h2><p>No admin functions connected.</p>")
@app.get("/phpmyadmin",response_class=HTMLResponse)
def phpmyadmin(): return HTMLResponse("<h2>Database console decoy</h2>")
@app.get("/shell")
def shell(cmd:str=""): return {"status":"simulated","message":"Commands are never executed."}
@app.get("/dashboard",response_class=HTMLResponse)
def dashboard(): return HTMLResponse("""<html><head><meta name=viewport content="width=device-width"><link rel=stylesheet href=/static/style.css></head><body><main><a href=/>Home</a><h1>Honeypot Dashboard</h1><p>Set ADMIN_TOKEN in Railway, then enter it here.</p><input id=t type=password placeholder=ADMIN_TOKEN><button onclick=load()>Load events</button><button onclick=toggle()>Toggle firewall</button><p id=s></p><pre id=o></pre></main><script>async function api(p,m='GET'){return fetch(p,{method:m,headers:{'X-Admin-Token':document.querySelector('#t').value}})}async function load(){let r=await api('/api/dashboard'),d=await r.json();document.querySelector('#s').textContent=r.ok?'Events: '+d.total+' | Blocked: '+d.blocked+' | Firewall: '+d.firewall_on:d.detail;document.querySelector('#o').textContent=JSON.stringify(d.events||[],null,2)}async function toggle(){let r=await api('/api/firewall/toggle','POST'),d=await r.json();document.querySelector('#s').textContent=d.detail||('Firewall: '+d.firewall_on);load()}</script></body></html>""")
def auth(x_admin_token): require(x_admin_token)
@app.get("/api/dashboard")
def data(x_admin_token:str=Header(default="")):
 auth(x_admin_token)
 with db() as c:
  total=c.execute("select count(*) from events").fetchone()[0]; blocked=c.execute("select count(*) from events where blocked=1").fetchone()[0]
  rows=[dict(r) for r in c.execute("select * from events order by id desc limit 100").fetchall()]
 return {"total":total,"blocked":blocked,"firewall_on":app.state.firewall,"events":rows}
@app.post("/api/firewall/toggle")
def toggle(x_admin_token:str=Header(default="")):
 auth(x_admin_token); app.state.firewall=not app.state.firewall; return {"firewall_on":app.state.firewall}
os.makedirs("static",exist_ok=True)
app.mount("/static",StaticFiles(directory="static"),name="static")
