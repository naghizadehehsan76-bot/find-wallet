# Wallet-Find v1 — بدون نیاز به نصب هیچ چیز اضافه (فقط Python 3). اجرا: python3 server.py
import http.server, json, sqlite3, hashlib, secrets, time, os, re, unicodedata
from urllib.parse import urlparse, parse_qs
DB = os.environ.get("DB", "wf.db"); PORT = int(os.environ.get("PORT", 8000))
SHARES = [0.60, 0.20, 0.10]; REST = 0.10      # سهم نفر ۱ تا ۳ و سهم مشترک بقیه
MAX_WRONG, LOCK_S = 3, 30
SCHEMA = """
create table if not exists users(id integer primary key,email text unique,name text,pw text,salt text,role text default 'USER');
create table if not exists sessions(token text primary key,uid int);
create table if not exists contests(id integer primary key,title text,start_ms int,end_ms int,gap_s int,prize real);
create table if not exists clues(cid int,step int,url text,hint text,ans text,primary key(cid,step));
create table if not exists joins(cid int,uid int,primary key(cid,uid));
create table if not exists prog(cid int,uid int,step int,solved_ms int,elapsed_ms int,primary key(cid,uid,step));
create table if not exists att(cid int,uid int,step int,wrong int default 0,locked_until int default 0,primary key(cid,uid,step));
"""
def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
def now(): return int(time.time() * 1000)
def norm(s):
    s = unicodedata.normalize("NFKC", str(s)).lower().replace("ي", "ی").replace("ك", "ک")
    return re.sub(r"\s+", " ", re.sub("[\u200c\u200d\u200e\u200f]", "", s)).strip()
def hans(s): return hashlib.sha256(("wf:" + norm(s)).encode()).hexdigest()
def pw_hash(p, salt): return hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 100000).hex()
class Err(Exception): pass

def status(ct, n=None):
    n = n or now()
    return "soon" if n < ct["start_ms"] else ("ended" if n >= ct["end_ms"] else "live")
def pick(c, cid):
    if cid: return c.execute("select * from contests where id=?", (cid,)).fetchone()
    n = now()
    return (c.execute("select * from contests where start_ms<=? and end_ms>? order by start_ms desc", (n, n)).fetchone()
         or c.execute("select * from contests where start_ms>? order by start_ms", (n,)).fetchone()
         or c.execute("select * from contests order by start_ms desc").fetchone())
def cinfo(ct): return {"id": ct["id"], "title": ct["title"], "start": ct["start_ms"], "end": ct["end_ms"], "gap": ct["gap_s"], "prize": ct["prize"], "status": status(ct), "now": now()}

def ranking(c, cid):
    ct = c.execute("select * from contests where id=?", (cid,)).fetchone()
    rows = c.execute("select u.id,u.name,sum(p.elapsed_ms) t,count(*) n from prog p join users u on u.id=p.uid where p.cid=? group by p.uid having n=12 order by t", (cid,)).fetchall()
    n = len(rows); pool = ct["prize"]
    base = [pool * SHARES[i] if i < 3 else pool * REST / (n - 3) for i in range(n)]
    out, i = [], 0
    while i < n:                                  # تساوی: جایزه‌ی رتبه‌های اشغال‌شده مساوی تقسیم می‌شود
        j = i
        while j < n and rows[j]["t"] == rows[i]["t"]: j += 1
        pr = sum(base[i:j]) / (j - i)
        for k in range(i, j): out.append({"uid": rows[k]["id"], "rank": i + 1, "name": rows[k]["name"], "total_ms": rows[k]["t"], "prize": round(pr, 4)})
        i = j
    return out

# ---------- routes ----------
def r_register(c, u, b, q):
    email, pw, name = norm(b.get("email", "")), str(b.get("password", "")), str(b.get("name", "")).strip()[:40]
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) or not name: raise Err("bad_input")
    if len(pw) < 6: raise Err("short_pw")
    if c.execute("select 1 from users where email=?", (email,)).fetchone(): raise Err("exists")
    first = c.execute("select count(*) from users").fetchone()[0] == 0
    salt = secrets.token_hex(8)
    uid = c.execute("insert into users(email,name,pw,salt,role) values(?,?,?,?,?)", (email, name, pw_hash(pw, salt), salt, "ADMIN" if first else "USER")).lastrowid
    return login_ok(c, uid)
def login_ok(c, uid):
    tok = secrets.token_hex(24); c.execute("insert into sessions values(?,?)", (tok, uid))
    return {"ok": 1, "_cookie": tok}
def r_login(c, u, b, q):
    r = c.execute("select * from users where email=?", (norm(b.get("email", "")),)).fetchone()
    if not r or not secrets.compare_digest(r["pw"], pw_hash(str(b.get("password", "")), r["salt"])): raise Err("bad_login")
    return login_ok(c, r["id"])
def r_logout(c, u, b, q): return {"ok": 1, "_cookie": ""}
def r_me(c, u, b, q): return {"user": {"name": u["name"], "role": u["role"]} if u else None}
def r_contest(c, u, b, q):
    ct = pick(c, None); return {"contest": cinfo(ct) if ct else None}
def r_join(c, u, b, q):
    if not u: raise Err("auth")
    ct = pick(c, b.get("cid"))
    if not ct or status(ct) != "live": raise Err("not_live")
    c.execute("insert or ignore into joins values(?,?)", (ct["id"], u["id"])); return {"ok": 1}
def r_state(c, u, b, q):
    ct = pick(c, q.get("cid"))
    if not ct: return {"contest": None}
    out = {"contest": cinfo(ct), "joined": False, "steps": []}
    if not u: return out
    cid, uid, n = ct["id"], u["id"], now()
    out["joined"] = bool(c.execute("select 1 from joins where cid=? and uid=?", (cid, uid)).fetchone())
    solved = {r["step"] for r in c.execute("select step from prog where cid=? and uid=?", (cid, uid))}
    for cl in c.execute("select * from clues where cid=? order by step", (cid,)):
        s = cl["step"]; pub = ct["start_ms"] + (s - 1) * ct["gap_s"] * 1000
        st = "solved" if s in solved else ("open" if out["joined"] and status(ct) == "live" and (s == 1 or s - 1 in solved) and n >= pub else "locked")
        a = c.execute("select locked_until from att where cid=? and uid=? and step=?", (cid, uid, s)).fetchone()
        d = {"step": s, "status": st, "publish": pub}
        if st in ("solved", "open"): d.update(url=cl["url"], hint=cl["hint"])
        if st == "open" and a: d["locked_until"] = a["locked_until"]
        out["steps"].append(d)
    return out
def r_answer(c, u, b, q):
    if not u: raise Err("auth")
    ct = pick(c, b.get("cid")); s = int(b.get("step", 0)); n = now()
    if not ct or status(ct, n) != "live": raise Err("closed")
    cid, uid = ct["id"], u["id"]
    if not c.execute("select 1 from joins where cid=? and uid=?", (cid, uid)).fetchone(): raise Err("not_joined")
    if c.execute("select 1 from prog where cid=? and uid=? and step=?", (cid, uid, s)).fetchone(): raise Err("done")
    if s > 1 and not c.execute("select 1 from prog where cid=? and uid=? and step=?", (cid, uid, s - 1)).fetchone(): raise Err("step_locked")
    pub = ct["start_ms"] + (s - 1) * ct["gap_s"] * 1000
    cl = c.execute("select * from clues where cid=? and step=?", (cid, s)).fetchone()
    if not cl or n < pub: raise Err("step_locked")
    c.execute("insert or ignore into att(cid,uid,step) values(?,?,?)", (cid, uid, s))
    a = c.execute("select * from att where cid=? and uid=? and step=?", (cid, uid, s)).fetchone()
    if a["locked_until"] > n: return {"err": "locked", "locked_until": a["locked_until"]}
    if hans(b.get("answer", "")) == cl["ans"]:
        c.execute("insert into prog values(?,?,?,?,?)", (cid, uid, s, n, n - pub))
        return {"ok": 1, "finished": s == 12}
    w = a["wrong"] + 1; lock = 0
    if w >= MAX_WRONG: w, lock = 0, n + LOCK_S * 1000
    c.execute("update att set wrong=?,locked_until=? where cid=? and uid=? and step=?", (w, lock, cid, uid, s))
    return {"err": "wrong", "locked_until": lock}
def r_results(c, u, b, q):
    ct = pick(c, q.get("cid"))
    if not ct: return {"contest": None}
    if status(ct) != "ended" and not (u and u["role"] == "ADMIN"): return {"contest": cinfo(ct), "rows": None}
    rk = ranking(c, ct["id"])
    mine = next((x for x in rk if u and x["uid"] == u["id"]), None)
    done = c.execute("select count(*) from prog where cid=? and uid=?", (ct["id"], u["id"])).fetchone()[0] if u else 0
    return {"contest": cinfo(ct), "rows": [{k: v for k, v in x.items() if k != "uid"} for x in rk], "mine": mine and mine["rank"], "done": done}
def admin(u):
    if not u or u["role"] != "ADMIN": raise Err("forbidden")
def r_admin_create(c, u, b, q):
    admin(u)
    lines = [l for l in str(b.get("clues", "")).split("\n") if l.strip()]
    if len(lines) != 12: raise Err("need12")
    st = now() + int(float(b.get("start_in_min", 0)) * 60000); dur = float(b.get("duration_min", 0))
    if dur <= 0: raise Err("bad_input")
    cid = c.execute("insert into contests(title,start_ms,end_ms,gap_s,prize) values(?,?,?,?,?)",
        (str(b.get("title", ""))[:80] or "Wallet-Find", st, st + int(dur * 60000), int(b.get("gap_s", 900)), float(b.get("prize", 10)))).lastrowid
    for i, l in enumerate(lines, 1):
        p = [x.strip() for x in l.split("|")]
        if len(p) != 3 or not p[2]: raise Err("bad_clue")
        c.execute("insert into clues values(?,?,?,?,?)", (cid, i, p[0], p[1], hans(p[2])))
    return {"ok": 1, "id": cid}
def r_admin_list(c, u, b, q):
    admin(u)
    return {"contests": [dict(cinfo(x), players=c.execute("select count(*) from joins where cid=?", (x["id"],)).fetchone()[0]) for x in c.execute("select * from contests order by id desc")]}

ROUTES = {("POST", "/api/register"): r_register, ("POST", "/api/login"): r_login, ("POST", "/api/logout"): r_logout,
 ("GET", "/api/me"): r_me, ("GET", "/api/contest"): r_contest, ("POST", "/api/join"): r_join, ("GET", "/api/state"): r_state,
 ("POST", "/api/answer"): r_answer, ("GET", "/api/results"): r_results, ("POST", "/api/admin/create"): r_admin_create, ("GET", "/api/admin/list"): r_admin_list}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def out(self, code, body, ctype="application/json", cookie=None):
        self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8"); self.send_header("Content-Length", str(len(body)))
        if cookie is not None: self.send_header("Set-Cookie", f"sid={cookie}; HttpOnly; Path=/; SameSite=Lax; Max-Age={2592000 if cookie else 0}")
        self.end_headers(); self.wfile.write(body)
    def handle_any(self, m):
        p = urlparse(self.path)
        if m == "GET" and not p.path.startswith("/api/"):
            return self.out(200, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"), "rb").read(), "text/html")
        fn = ROUTES.get((m, p.path))
        if not fn: return self.out(404, b'{"err":"404"}')
        c = db()
        try:
            n = int(self.headers.get("Content-Length") or 0); b = json.loads(self.rfile.read(n) or b"{}") if n else {}
            q = {k: v[0] for k, v in parse_qs(p.query).items()}
            ck = re.search(r"sid=(\w+)", self.headers.get("Cookie", "")); u = None
            if ck:
                u = c.execute("select u.* from sessions s join users u on u.id=s.uid where s.token=?", (ck.group(1),)).fetchone()
            res = fn(c, u, b, q); c.commit(); ck = res.pop("_cookie", None) if isinstance(res, dict) else None
            self.out(200, json.dumps(res).encode(), cookie=ck)
        except Err as e: c.rollback(); self.out(400, json.dumps({"err": str(e)}).encode())
        except Exception as e: c.rollback(); self.out(500, json.dumps({"err": "server", "detail": str(e)}).encode())
        finally: c.close()
    def do_GET(self): self.handle_any("GET")
    def do_POST(self): self.handle_any("POST")

if __name__ == "__main__":
    c = db(); c.executescript(SCHEMA); c.commit(); c.close()
    print(f"Wallet-Find on http://0.0.0.0:{PORT}  (اولین کاربر ثبت‌نام‌شده = مدیر)")
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
