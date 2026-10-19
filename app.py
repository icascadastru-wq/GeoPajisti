"""GeoPajiști v0.8 - all field sheets per municipality in one printable file."""
import csv, hashlib, hmac, html, io, json, os, secrets, sqlite3, threading, re, zipfile
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'geopajisti.sqlite3'))
PORT = int(os.environ.get('PORT', '8000'))
SESSIONS = {}
LOCK = threading.Lock()
def conn():
    c = sqlite3.connect(DB, timeout=20)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def init_db():
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'specialist');
        CREATE TABLE IF NOT EXISTS municipalities(id INTEGER PRIMARY KEY, name TEXT NOT NULL, district TEXT NOT NULL DEFAULT '', UNIQUE(name,district));
        CREATE TABLE IF NOT EXISTS units(id INTEGER PRIMARY KEY, municipality_id INTEGER NOT NULL REFERENCES municipalities(id), code TEXT NOT NULL, name TEXT DEFAULT '', area REAL NOT NULL DEFAULT 0, UNIQUE(municipality_id,code));
        CREATE TABLE IF NOT EXISTS forms(id INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL REFERENCES units(id), inventory_date TEXT NOT NULL, author TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'Ciornă', locality TEXT DEFAULT '', altitude_min REAL, altitude_max REAL, slope REAL, aspect TEXT DEFAULT '', relief TEXT DEFAULT '', previous_management TEXT DEFAULT '', functional_group TEXT DEFAULT '', land_use TEXT DEFAULT '', watering_source TEXT DEFAULT '', landslide_ha REAL, erosion_ha REAL, moisture_ha REAL, stones_ha REAL, grass_cover_pct REAL, ruderal_pct REAL, woody_cover_pct REAL, pasture_type_code TEXT DEFAULT '', pasture_type_name TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS species(id INTEGER PRIMARY KEY, form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE, category TEXT NOT NULL, scientific_name TEXT NOT NULL, common_name TEXT DEFAULT '', participation_pct REAL);
        CREATE TABLE IF NOT EXISTS works(id INTEGER PRIMARY KEY, form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE, title TEXT NOT NULL, years TEXT DEFAULT '', area_ha REAL, notes TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT, happened_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS user_municipalities(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, municipality_id INTEGER NOT NULL REFERENCES municipalities(id) ON DELETE CASCADE, PRIMARY KEY(user_id, municipality_id));
        CREATE TABLE IF NOT EXISTS species_catalog(id INTEGER PRIMARY KEY, scientific_name TEXT NOT NULL UNIQUE COLLATE NOCASE, common_name TEXT NOT NULL DEFAULT '', family TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'Alte familii botanice', source TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS form_history(id INTEGER PRIMARY KEY,
            form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
            action TEXT NOT NULL, changed_by TEXT NOT NULL, happened_at TEXT NOT NULL,
            previous_json TEXT NOT NULL, current_json TEXT NOT NULL, details TEXT NOT NULL DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_form_history_form ON form_history(form_id,id);
        ''')
        # Migrations preserve original UA, forms, species, and works.
        # Add specialist first and last names without rebuilding any old records.
        user_cols = {r['name'] for r in c.execute('PRAGMA table_info(users)')}
        for name in ('first_name', 'last_name'):
            if name not in user_cols:
                c.execute(f"ALTER TABLE users ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
        cols = {r['name'] for r in c.execute('PRAGMA table_info(forms)')}
        for name, decl in [('created_by','TEXT'), ('assigned_to','TEXT'), ('decision_by','TEXT'), ('decision_at','TEXT'), ('return_reason','TEXT'), ('approval_mode','TEXT')]:
            if name not in cols: c.execute(f'ALTER TABLE forms ADD COLUMN {name} {decl}')
        cols = {r['name'] for r in c.execute('PRAGMA table_info(species)')}
        if 'catalog_id' not in cols:
            c.execute('ALTER TABLE species ADD COLUMN catalog_id INTEGER REFERENCES species_catalog(id)')
        c.execute("UPDATE users SET role='specialist' WHERE role='editor'")
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            pw = os.environ.get('ADMIN_PASSWORD')
            if not pw:
                raise RuntimeError('Setați ADMIN_PASSWORD în variabilele de mediu înainte de prima pornire.')
            salt = secrets.token_hex(16)
            digest = hashlib.pbkdf2_hmac('sha256',pw.encode(),bytes.fromhex(salt),210000).hex()
            c.execute('INSERT INTO users(username,salt,password_hash,role) VALUES (?,?,?,?)',('admin',salt,digest,'admin'))

def esc(v): return html.escape(str(v if v is not None else ''), quote=True)
def num(v):
    try: return float(str(v).replace(',','.')) if str(v).strip() else None
    except (ValueError,TypeError): return None
def sqlint(v):
    try: return int(v)
    except (ValueError,TypeError): return 0

ROLES = {'admin':'Administrator', 'specialist':'Specialist în teren', 'aprobator':'Aprobator'}

def full_name(user):
    name=' '.join(part.strip() for part in (user['first_name'],user['last_name']) if part and part.strip())
    return name or user['username']

def safe_filename(value):
    value=re.sub(r'[^\w.-]+','_',str(value),flags=re.UNICODE).strip('_.')
    return value[:60] or 'fisier'

STATUSES = ('Ciornă','Transmisă','Returnată','Aprobată')

def can_municipality(c,u,mid):
    if u['role']=='admin': return True
    return bool(c.execute('''SELECT 1 FROM user_municipalities a
        JOIN users usr ON usr.id=a.user_id
        WHERE usr.username=? AND a.municipality_id=?''',(u['name'],mid)).fetchone())

def unit_access(c,u,uid):
    row=c.execute('SELECT municipality_id FROM units WHERE id=?',(uid,)).fetchone()
    return bool(row and can_municipality(c,u,row['municipality_id']))

def form_access(c,u,fid):
    row=c.execute('SELECT u.municipality_id FROM forms f JOIN units u ON u.id=f.unit_id WHERE f.id=?',(fid,)).fetchone()
    return bool(row and can_municipality(c,u,row['municipality_id']))

def can_edit(u,form_row):
    if form_row['status'] not in ('Ciornă','Returnată'): return False
    return u['role']=='admin' or (u['role']=='specialist' and u['name'] in (form_row['created_by'],form_row['assigned_to']))

def form_snapshot(c, fid):
    """Return the complete editable record and dependent observations in one transaction."""
    record=c.execute('SELECT * FROM forms WHERE id=?',(fid,)).fetchone()
    if record is None:
        return None
    snapshot={
        'form':dict(record),
        'species':[dict(row) for row in c.execute(
            'SELECT * FROM species WHERE form_id=? ORDER BY id',(fid,))],
        'works':[dict(row) for row in c.execute(
            'SELECT * FROM works WHERE form_id=? ORDER BY id',(fid,))],
    }
    if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='soils'").fetchone():
        snapshot['soils']=[dict(row) for row in c.execute(
            'SELECT * FROM soils WHERE form_id=? ORDER BY id',(fid,))]
    return snapshot


def record_form_change(c, fid, action, username, now, before, details=''):
    """Persist full before/after snapshots for forensic review of corrections."""
    after=form_snapshot(c,fid)
    c.execute("""INSERT INTO form_history(form_id,action,changed_by,happened_at,
            previous_json,current_json,details) VALUES (?,?,?,?,?,?,?)""",
        (fid,action,username,now,
         json.dumps(before,ensure_ascii=False,default=str) if before is not None else '{}',
         json.dumps(after,ensure_ascii=False,default=str) if after is not None else '{}',
         details))


def form_history_html(c, fid):
    rows=c.execute('SELECT * FROM form_history WHERE form_id=? ORDER BY id DESC',(fid,)).fetchall()
    if not rows:
        return '<details class="card"><summary>Istoric modificări</summary><p class="muted">Nu există încă modificări înregistrate în această versiune.</p></details>'
    headings={'inventory_date':'Data inventarierii','author':'Specialist','locality':'Trup / localitate',
        'altitude_min':'Altitudine minimă','altitude_max':'Altitudine maximă',
        'slope':'Înclinare','aspect':'Expoziție','relief':'Relief',
        'previous_management':'Gospodărirea anterioară','functional_group':'Grupa funcțională',
        'land_use':'Categoria de folosință','watering_source':'Sursa de adăpare',
        'landslide_ha':'Alunecări (ha)','erosion_ha':'Eroziune (ha)',
        'moisture_ha':'Exces de umiditate (ha)','stones_ha':'Petriș (ha)',
        'grass_cover_pct':'Covor ierbos (%)','ruderal_pct':'Veget. ruderală (%)',
        'woody_cover_pct':'Veget. lemnoasă (%)','pasture_type_code':'Cod tip pajiște',
        'pasture_type_name':'Tip pajiște','notes':'Observații',
        'status':'Statut','decision_by':'Statut actualizat de','decision_at':'Data aprobării',
        'approval_mode':'Tip aprobare','return_reason':'Motiv returnare'}
    parts=[]
    for row in rows:
        before=json.loads(row['previous_json'] or '{}')
        after=json.loads(row['current_json'] or '{}')
        old=before.get('form') or {};new=after.get('form') or {}
        changes=[]
        for key,label in headings.items():
            if old.get(key)!=new.get(key):
                changes.append(f'<tr><td>{esc(label)}</td><td>{esc(old.get(key))}</td><td>{esc(new.get(key))}</td></tr>')
        for table,label in [('species','Specii'),('works','Lucrări'),('soils','Soluri')]:
            if before.get(table,[])!=after.get(table,[]):
                # Entire before and after lists remain available in immutable JSON snapshots.
                changes.append(f'<tr><td>{esc(label)}</td><td>{esc(len(before.get(table,[])))} înregistrări</td><td>{esc(len(after.get(table,[])))} înregistrări</td></tr>')
        summary=f'{esc(row["happened_at"])} · {esc(row["changed_by"])} · {esc(row["action"])}'
        details=f'<p>{esc(row["details"])}</p>' if row['details'] else ''
        tbl=('<table><tr><th>Câmp</th><th>Înainte</th><th>După</th></tr>'+''.join(changes)+'</table>' if changes else '<p>Operație înregistrată.</p>')
        parts.append(f'<details><summary>{summary}</summary>{details}{tbl}</details>')
    return '<div class="card"><h2>Istoric modificări și reaprobări</h2><p class="muted">Se păstrează versiunea de dinainte și cea de după fiecare modificare. Înregistrările anterioare acestei actualizări nu pot fi reconstruite retroactiv.</p>'+''.join(parts)+'</div>'


def pw_hash(password):
    salt=secrets.token_hex(16)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),210000).hex()
    return salt,digest

# Basic Office Open XML for Excel export; no runtime dependencies.
def make_xlsx(sheets):
    def xml_cell(value, row, col):
        col_name=''; q=col
        while q: q,part=divmod(q-1,26); col_name=chr(65+part)+col_name
        ref=f'{col_name}{row}'
        # Export strings as strings; never evaluate user-supplied formulas.
        if isinstance(value,(int,float)) and not isinstance(value,bool):
            return f'<c r="{ref}" t="n" s="{1 if row==1 else 0}"><v>{value}</v></c>'
        safe_value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', '' if value is None else str(value))
        txt=xml_escape(safe_value, {'"':'&quot;'})
        return f'<c r="{ref}" t="inlineStr" s="{1 if row==1 else 0}"><is><t xml:space="preserve">{txt}</t></is></c>'
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml','''<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
'''+''.join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1,len(sheets)+1))+'</Types>')
        z.writestr('_rels/.rels','''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>''')
        z.writestr('xl/workbook.xml','''<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'''+''.join(f'<sheet name="{xml_escape(name)}" sheetId="{i}" r:id="rId{i}"/>' for i,(name,_) in enumerate(sheets,1))+'</sheets></workbook>')
        z.writestr('xl/_rels/workbook.xml.rels','''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'''+''.join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1,len(sheets)+1))+f'<Relationship Id="rId{len(sheets)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        z.writestr('xl/styles.xml','''<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF205B46"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFill="1" applyFont="1"/></cellXfs></styleSheet>''')
        for i,(name,rows) in enumerate(sheets,1):
            sheet='<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetData>'
            for r_idx,row in enumerate(rows,1):
                sheet+=f'<row r="{r_idx}">'+''.join(xml_cell(v,r_idx,j) for j,v in enumerate(row,1))+'</row>'
            sheet+='</sheetData>'
            if rows:
                ncols=len(rows[0]); letter=''; a=ncols
                while a: a,d=divmod(a-1,26); letter=chr(65+d)+letter
                sheet+=f'<autoFilter ref="A1:{letter}{max(len(rows),1)}"/>'
            sheet+='</worksheet>'
            z.writestr(f'xl/worksheets/sheet{i}.xml',sheet)
    return out.getvalue()

def field(name,label,value='',typ='text',step=None):
    stepattr=f' step="{step}"' if step else ''
    return f'<label>{esc(label)}<input type="{typ}" name="{esc(name)}" value="{esc(value)}"{stepattr}></label>'
def select(name, opts, current=''):
    return '<select name="%s">%s</select>' %(esc(name),''.join('<option value="%s" %s>%s</option>'%(esc(x),'selected' if x==current else '',esc(x)) for x in opts))
def layout(title, content, username=None):
    user_menu = (' <a href="/utilizatori">Utilizatori</a>'
        if isinstance(username,dict) and username.get('role')=='admin' else '')
    nav = ('<nav><a href="/">GeoPajiști</a> <a href="/primarii">Primării / UA</a> <a href="/specii">Banca de specii</a> <a href="/rapoarte">Rapoarte Excel</a>'+user_menu+' <a href="/logout">Ieșire</a></nav>' if username else '')
    return f'''<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} · GeoPajiști</title>
<style>body{{margin:0;background:#f4f6f3;color:#20352a;font:16px system-ui,Arial}} nav{{background:#1b503c;padding:18px;display:flex;gap:22px;flex-wrap:wrap}}nav a{{color:white}}main{{max-width:1100px;margin:32px auto;padding:0 16px}}.card{{background:white;padding:22px;border:1px solid #dce4dc;border-radius:12px;margin:18px 0}}h1{{font-size:26px}}h2{{font-size:20px}}h3{{font-size:17px}}a{{color:#186747}}table{{border-collapse:collapse;width:100%;background:#fff}}th,td{{padding:10px;border-bottom:1px solid #e0e6e0;text-align:left;vertical-align:top}}th{{background:#edf3ed}}input,select,textarea{{width:100%;padding:10px;border:1px solid #b8c8bc;border-radius:6px;box-sizing:border-box;font:inherit;margin-top:5px}}label{{display:block;font-size:14px;font-weight:600;margin:10px 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}}button,.btn{{display:inline-block;border:0;border-radius:7px;background:#206f4e;color:white;padding:10px 15px;cursor:pointer;text-decoration:none;font:inherit}}.secondary{{background:#e7f0e8;color:#16503a}}.muted{{color:#647469}}.actions{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}details{{background:white;margin:10px 0;border-radius:10px;padding:14px;border:1px solid #dce4dc}}summary{{font-weight:700;cursor:pointer}}.error{{background:#ffe8e8;color:#8d2020;padding:12px}}@media print{{nav,.actions,.no-print,button{{display:none!important}}body{{background:white}}main{{max-width:none}}.card{{border:0;padding:2px}}}}</style></head><body>{nav}<main>{content}</main></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def send_page(self,page,status=200,cookie=None,content_type='text/html; charset=utf-8',attachment=None):
        raw=page.encode('utf-8') if isinstance(page,str) else page
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(raw)))
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','same-origin')
        self.send_header('Cache-Control','no-store')
        if cookie:self.send_header('Set-Cookie',cookie)
        if attachment:self.send_header('Content-Disposition',f'attachment; filename="{attachment}"')
        self.end_headers(); self.wfile.write(raw)
    def redirect(self,path,cookie=None):
        self.send_response(303);self.send_header('Location',path)
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers()
    def data(self):
        n=int(self.headers.get('Content-Length','0'))
        if n>2000000: raise ValueError('Formular prea mare')
        return {k:v[-1] for k,v in parse_qs(self.rfile.read(n).decode(),keep_blank_values=True).items()}
    def user(self):
        cookies=SimpleCookie()
        try:cookies.load(self.headers.get('Cookie',''))
        except: return None
        token=cookies.get('gp_session')
        return SESSIONS.get(token.value) if token else None
    def csrf(self,f):
        u=self.user();return bool(u and hmac.compare_digest(f.get('csrf',''),u['csrf']))
    def hidden(self):return f'<input type="hidden" name="csrf" value="{esc(self.user()["csrf"])}">'
    def error(self,msg,status=400):self.send_page(layout('Eroare',f'<div class="error">{esc(msg)}</div><a href="/">Înapoi</a>',self.user()),status)
    def do_GET(self):
        p=urlparse(self.path);route=p.path;u=self.user()
        if route=='/health':return self.send_page('ok',content_type='text/plain')
        if route=='/login':return self.send_page(layout('Autentificare','<h1>Autentificare</h1><form class="card" method="post" action="/login">'+field('username','Utilizator')+field('password','Parolă','','password')+'<button>Intră</button></form>'))
        if route=='/logout':
            if u:
                for k,v in list(SESSIONS.items()):
                    if v is u: SESSIONS.pop(k,None)
            return self.redirect('/login','gp_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')
        if not u:return self.redirect('/login')
        with conn() as c:
            if route=='/utilizatori':
                if u['role']!='admin':return self.error('Acces rezervat administratorului',403)
                accounts=c.execute('SELECT id,username,role,first_name,last_name FROM users ORDER BY username').fetchall()
                munis=c.execute('SELECT id,name FROM municipalities ORDER BY name').fetchall()
                lines=''
                for a in accounts:
                    assigned=c.execute('SELECT m.name FROM user_municipalities am JOIN municipalities m ON am.municipality_id=m.id WHERE am.user_id=? ORDER BY m.name',(a['id'],)).fetchall()
                    remove = ('<span class="muted">Cont curent</span>' if a['username']==u['name'] else (
                        '<form method="post" action="/utilizatori/delete" class="no-print" '
                        'onsubmit="return confirm(\'Ștergi contul selectat? Fișele sale vor rămâne înregistrate.\')">'
                        + self.hidden() + f'<input type="hidden" name="user_id" value="{a["id"]}">'
                        + '<button type="submit" style="background:#b42318">Șterge utilizator</button></form>'))
                    profile=(f'<form class="no-print" method="post" action="/utilizatori/nume">'
                        + self.hidden()+f'<input type="hidden" name="user_id" value="{a["id"]}">'
                        +'<div class="grid">'
                        +field('first_name','Prenume',a['first_name'])
                        +field('last_name','Nume',a['last_name'])
                        +'</div><button class="secondary">Salvează numele</button></form>')
                    lines+=f'<tr><td><b>{esc(a["username"])}</b><br>{esc(full_name(a))}</td><td>{esc(ROLES.get(a["role"],a["role"]))}</td><td>{esc(", ".join(x["name"] for x in assigned) or "—")}</td><td>{profile}{remove}</td></tr>'
                form=f'<form class="card" method="post" action="/utilizatori/new">{self.hidden()}<h2>Utilizator nou</h2>{field("first_name","Prenume")}{field("last_name","Nume")}{field("username","Utilizator")}{field("password","Parolă inițială (minimum 12 caractere)","","password")}<label>Rol<select name="role"><option value="specialist">Specialist în teren</option><option value="aprobator">Aprobator</option><option value="admin">Administrator</option></select></label><button>Creează cont</button></form>'
                opts=''.join(f'<option value="{a["id"]}">{esc(a["username"])} ({esc(ROLES.get(a["role"],a["role"]))})</option>' for a in accounts if a['role']!='admin')
                mopts=''.join(f'<option value="{m["id"]}">{esc(m["name"])}</option>' for m in munis)
                assignments=f'<form class="card" method="post" action="/utilizatori/acces">{self.hidden()}<h2>Acces pe primării</h2><label>Utilizator<select name="user_id">{opts}</select></label><label>Primărie<select name="municipality_id">{mopts}</select></label><label>Acțiune{select("action",["acorda","revoca"])}</label><button>Actualizează accesul</button></form>'
                return self.send_page(layout('Utilizatori','<h1>Utilizatori și drepturi</h1><p>Completează numele și prenumele pentru fiecare specialist. În fișele noi, specialistul va apărea automat cu numele complet.</p><table><tr><th>Cont / Specialist</th><th>Rol</th><th>Primării atribuite</th><th>Acțiuni</th></tr>'+lines+'</table>'+form+assignments,u))
            if route=='/specii':
                rows=c.execute('SELECT * FROM species_catalog ORDER BY active DESC, scientific_name').fetchall()
                table=''.join(f'<tr><td><i>{esc(r["scientific_name"])}</i></td><td>{esc(r["common_name"])}</td><td>{esc(r["family"])}</td><td>{esc(r["category"])}</td><td>{"Activă" if r["active"] else "Inactivă"}</td></tr>' for r in rows)
                form=''
                if u['role']=='admin':
                    form=f'<form class="card" method="post" action="/catalog/new">{self.hidden()}<h2>Adaugă specie în nomenclator</h2>{field("scientific_name","Denumirea științifică")}{field("common_name","Denumirea populară")}{field("family","Familia botanică")}<label>Grupa{select("category",["Graminee","Fabacee","Alte familii botanice","Vegetație lemnoasă"])}</label>{field("source","Sursa taxonomică / document de referință")}<button>Adaugă în bancă</button></form>'
                return self.send_page(layout('Banca de specii',f'<h1>Banca de specii</h1><p class="muted">Nomenclator comun tuturor primăriilor. Se introduc numai denumiri verificate; lista pornește goală.</p><table><tr><th>Specie</th><th>Denumire populară</th><th>Familie</th><th>Grup</th><th>Stare</th></tr>{table}</table>'+form,u))
            if route in ('/','/primarii'):
                records=c.execute('''SELECT m.*,COUNT(DISTINCT un.id) units,COUNT(DISTINCT f.id) forms FROM municipalities m
                    LEFT JOIN units un ON un.municipality_id=m.id LEFT JOIN forms f ON f.unit_id=un.id
                    WHERE (?='admin' OR EXISTS (SELECT 1 FROM user_municipalities a JOIN users usr ON usr.id=a.user_id WHERE a.municipality_id=m.id AND usr.username=?))
                    GROUP BY m.id ORDER BY m.name''',(u['role'],u['name'])).fetchall()
                lines=''.join(f'<tr><td><a href="/primarie/{r["id"]}">{esc(r["name"])}</a></td><td>{esc(r["district"])}</td><td>{r["units"]}</td><td>{r["forms"]}</td></tr>' for r in records)
                form=(f'<form method="post" action="/primarii" class="card"><h2>Adaugă primărie</h2>{self.hidden()}<div class="grid">{field("name","Denumire primărie")}{field("district","Raion")}</div><button>Adaugă</button></form>' if u['role']=='admin' else '')
                content=f'<h1>Primării</h1><p class="muted">Primărie → UA → Fișe de teren</p><table><tr><th>Primărie</th><th>Raion</th><th>UA</th><th>Fișe</th></tr>{lines}</table>'+form
                return self.send_page(layout('Primării',content,u))
            if route.startswith('/primarie/'):
                mid=sqlint(route.rsplit('/',1)[1]);m=c.execute('SELECT * FROM municipalities WHERE id=?',(mid,)).fetchone()
                if not m:return self.error('Primăria nu există',404)
                if not can_municipality(c,u,mid):return self.error('Nu ai acces la această primărie',403)
                rows=c.execute('SELECT u.*, (SELECT COUNT(*) FROM forms f WHERE f.unit_id=u.id) forms FROM units u WHERE municipality_id=? ORDER BY code',(mid,)).fetchall()
                
                table = ''
                for r in rows:
                    delete_button = ''

                    if u['role'] == 'admin':
                        if r['forms'] == 0:
                            delete_button = (
                                '<form method="post" action="/ua/delete" '
                                'onsubmit="return confirm(\'Sigur ștergi definitiv UA și denumirea ei?\')" '
                                'style="display:inline-block;margin-left:10px">'
                                + self.hidden()
                                + f'<input type="hidden" name="id" value="{r["id"]}">'
                                + '<button type="submit" style="background:#b42318">Șterge UA</button></form>'
                            )
                        else:
                            delete_button = (f'<button disabled title="Șterge mai întâi cele {r["forms"]} fișe" '
                                'style="background:#a5aaa5;cursor:not-allowed;margin-left:10px">Șterge UA</button>'
                                '<small class="muted"> (mai întâi șterge fișele)</small>')

                    table += (
                        f'<tr><td><a href="/ua/{r["id"]}">{esc(r["code"])}</a></td>'
                        f'<td>{esc(r["name"])}</td>'
                        f'<td>{esc(r["area"])}</td>'
                        f'<td>{r["forms"]}{delete_button}</td></tr>'
                    )
                form=(f'<form method="post" action="/ua/new" class="card"><h2>UA nouă</h2>{self.hidden()}<input type="hidden" name="municipality_id" value="{mid}"><div class="grid">{field("code","Cod UA")}{field("name","Denumirea sectorului")}{field("area","Suprafața (ha)","","number","any")}</div><button>Adaugă UA</button></form>' if u['role']=='admin' else '')
                download=(f'<div class="actions"><a class="btn secondary" href="/export-xlsx?primarie={mid}&status=Toate">'
                    'Descarcă toate datele primăriei (.xlsx)</a>'
                    +f'<a class="btn" href="/fise-primarie?primarie={mid}" target="_blank">'
                    'Toate fișele A4 într-un singur PDF</a></div>'
                    +'<p class="muted">Deschide toate fișele într-un singur document, apoi selectează Imprimă → Salvare ca PDF. Fiecare fișă este pe o pagină A4.</p>')
                return self.send_page(layout('Primărie',f'<a href="/primarii">← Primării</a><h1>{esc(m["name"])}</h1>'
                    + download + f'<table><tr><th>UA</th><th>Denumire</th><th>Suprafață (ha)</th><th>Fișe / Ștergere UA</th></tr>{table}</table>'+form,u))
            if route.startswith('/ua/'):
                uid=sqlint(route.rsplit('/',1)[1]);unit=c.execute('SELECT u.*,m.name municipality FROM units u JOIN municipalities m ON u.municipality_id=m.id WHERE u.id=?',(uid,)).fetchone()
                if not unit:return self.error('UA nu există',404)
                if not can_municipality(c,u,unit['municipality_id']):return self.error('Acces interzis',403)
                rows=c.execute('SELECT * FROM forms WHERE unit_id=? ORDER BY inventory_date DESC,id DESC',(uid,)).fetchall()
                lines=''.join(f'<tr><td><a href="/fisa/{r["id"]}">Fișa #{r["id"]}</a></td><td>{esc(r["inventory_date"])}</td><td>{esc(r["author"])}</td><td>{esc(r["status"])}</td></tr>' for r in rows)
                form=''
                if u['role'] in ('admin','specialist'):
                    current_usr=c.execute('SELECT * FROM users WHERE username=?',(u['name'],)).fetchone()
                    current_name=full_name(current_usr) if current_usr else u['name']
                    if u['role']=='admin':
                        available=c.execute('''SELECT DISTINCT usr.username,usr.first_name,usr.last_name FROM users usr
                            LEFT JOIN user_municipalities a ON a.user_id=usr.id
                            WHERE usr.username=? OR (usr.role='specialist' AND a.municipality_id=?)
                            ORDER BY usr.last_name,usr.first_name,usr.username''',(u['name'],unit['municipality_id'])).fetchall()
                        author_input='<label>Specialist<select name="author_username">'+''.join(
                            f'<option value="{esc(person["username"])}"'+(' selected' if person['username']==u['name'] else '')
                            +f'>{esc(full_name(person))} ({esc(person["username"])})</option>' for person in available)+'</select></label>'
                    else:
                        author_input=(f'<label>Specialist (din contul autentificat)<input value="{esc(current_name)}" readonly></label>'
                                      '<p class="muted">Numele se completează în meniul „Utilizatori”, de către administrator.</p>')
                    form=(f'<form method="post" action="/fisa/new" class="card"><h2>Înregistrare fișă nouă</h2>{self.hidden()}'
                          +f'<input type="hidden" name="unit_id" value="{uid}"><div class="grid">'
                          +field('inventory_date','Data inventarierii',datetime.now().strftime('%Y-%m-%d'),'date')
                          +author_input+'</div><button>Creare fișă</button></form>')
                return self.send_page(layout('Unitate amenajistică',f'<a href="/primarie/{unit["municipality_id"]}">← Primărie</a><h1>{esc(unit["municipality"])} / UA {esc(unit["code"])}</h1><p>Suprafața UA: {esc(unit["area"])} ha</p><table><tr><th>Fișa</th><th>Data</th><th>Specialist</th><th>Stare</th></tr>{lines}</table>'+form,u))
            if route.startswith('/fisa/'):
                fid=sqlint(route.rsplit('/',1)[1]);r=c.execute('SELECT f.*,u.code,u.area,u.municipality_id,m.name municipality FROM forms f JOIN units u ON f.unit_id=u.id JOIN municipalities m ON u.municipality_id=m.id WHERE f.id=?',(fid,)).fetchone()
                if not r:return self.error('Fișa nu există',404)
                if not can_municipality(c,u,r['municipality_id']):return self.error('Acces interzis',403)
                species=c.execute('SELECT * FROM species WHERE form_id=? ORDER BY category,id',(fid,)).fetchall()
                works=c.execute('SELECT * FROM works WHERE form_id=? ORDER BY id',(fid,)).fetchall()
                if p.query=='print':return self.send_page(self.print_form(r,species,works))
                return self.send_page(layout(f'Fișa #{fid}',self.edit_form(r,species,works)+form_history_html(c,fid),u))
            if route=='/fise-primarie':
                mid=sqlint(parse_qs(p.query).get('primarie',['0'])[0])
                m=c.execute('SELECT name FROM municipalities WHERE id=?',(mid,)).fetchone()
                if not m:return self.error('Primăria nu există',404)
                if not can_municipality(c,u,mid):return self.error('Acces interzis',403)
                records=c.execute('''SELECT f.*,un.code,un.area,un.municipality_id,m.name AS municipality
                    FROM forms f JOIN units un ON un.id=f.unit_id
                    JOIN municipalities m ON m.id=un.municipality_id
                    WHERE m.id=? ORDER BY un.code,f.inventory_date,f.id''',(mid,)).fetchall()
                # Un singur document imprimabil (fără ZIP și fără dependențe externe).
                # Browserul permite Salvare ca PDF, cu câte o pagină A4 pentru fiecare fișă.
                if not records:
                    return self.send_page(layout('Fișe pentru primărie',
                        f'<h1>{esc(m["name"])} – fișe de teren</h1>'
                        '<p>Primăria nu are încă fișe de teren pentru descărcare.</p>',u))
                sheet_html=[]
                for form in records:
                    fid=form['id']
                    spec=c.execute('SELECT * FROM species WHERE form_id=? ORDER BY category,id',(fid,)).fetchall()
                    works=c.execute('SELECT * FROM works WHERE form_id=? ORDER BY id',(fid,)).fetchall()
                    rendered=self.print_form(form,spec,works,offline=True)
                    # Reutilizăm macheta A4 deja verificată, fără bara de navigare
                    # sau alte elemente ce ar dubla antetul în documentul multipagină.
                    start=rendered.find('<main id="print-sheet">')
                    end=rendered.find('</main>',start)
                    if start<0 or end<0:
                        return self.error('Șablonul A4 nu a putut fi pregătit',500)
                    inner=rendered[start+len('<main id="print-sheet">'):end]
                    sheet_html.append('<section class="sheet"><div class="sheet-inner">'+inner+'</div></section>')
                combined='''<!doctype html><html lang="ro"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fișele de teren – '''+esc(m['name'])+'''</title>
<style>
@page{size:A4 landscape;margin:7mm}
*{box-sizing:border-box}
body{margin:0;background:#e9eee9;color:#192f25;font:12px Arial,sans-serif}
.toolbar{background:#fff;padding:12px;position:sticky;top:0;z-index:2;box-shadow:0 1px 5px #ccc;display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap}
.toolbar button,.toolbar a{background:#206f4e;color:white;padding:10px 14px;border:0;border-radius:6px;cursor:pointer;text-decoration:none;font-size:14px}
.toolbar .secondary{background:#e4ece6;color:#205b46}
.sheet{width:283mm;height:196mm;overflow:hidden;margin:12px auto;background:white;box-shadow:0 2px 10px #bbb;break-after:page;page-break-after:always}
.sheet:last-child{break-after:auto;page-break-after:auto}
.sheet-inner{width:283mm;padding:4mm;transform-origin:top left}
h1{text-align:center;font-size:17px;margin:0 0 3px}
.sub{text-align:center;font-size:10px;margin-bottom:5px}
h2{font-size:12px;background:#e8efe9;padding:2px 5px;margin:5px 0 2px;border-left:3px solid #32664a}
.data-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:2px 7px}
.field{font-size:11px;padding:1px 2px;border-bottom:1px solid #e8ece8;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{font-size:10.5px;padding:2px 3px;border:1px solid #cbd7cc;text-align:left;overflow-wrap:anywhere}
th{background:#e8efe9}
@media print{
 body{background:white}.toolbar{display:none!important}
 .sheet{width:283mm;height:196mm;margin:0;box-shadow:none;break-after:page;page-break-after:always}
 .sheet:last-child{break-after:auto;page-break-after:auto}
 *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
</style></head><body>'''
                combined+=('<div class="toolbar"><strong>'+esc(m['name'])+f' – {len(records)} fișe</strong>'
                    '<button type="button" onclick="window.print()">Imprimă / Salvează într-un singur PDF</button>'
                    f'<a class="secondary" href="/fise-primarie?primarie={mid}&download=1">'
                    'Descarcă un singur fișier HTML</a></div>')
                combined+=''.join(sheet_html)
                combined+='''<script>
function fitSheets(){
 const maxHeight=196*96/25.4, maxWidth=283*96/25.4;
 document.querySelectorAll('.sheet-inner').forEach(el=>{
   el.style.transform='none';
   const scale=Math.min(1,maxHeight/el.scrollHeight,maxWidth/el.scrollWidth);
   el.style.transform='scale('+Math.max(scale,0.05)+')';
 });
}
window.addEventListener('load',fitSheets);
window.addEventListener('beforeprint',fitSheets);
</script></body></html>'''
                if parse_qs(p.query).get('download',['0'])[0]=='1':
                    filename=f'GeoPajisti_fise_primarie_{mid}.html'
                    return self.send_page(combined,attachment=filename)
                return self.send_page(combined)
            if route=='/rapoarte':
                mids=c.execute('SELECT id,name FROM municipalities ORDER BY name').fetchall()
                options='<option value="0">Toate primăriile accesibile</option>'+''.join(f'<option value="{m["id"]}">{esc(m["name"])}</option>' for m in mids if can_municipality(c,u,m['id']))
                filters=f'<form action="/export-xlsx" method="get" class="card"><h2>Centralizatoare Excel</h2><label>Primăria<select name="primarie">{options}</select></label><label>Statut{select("status",["Toate","Aprobate","Ciornă","Transmisă","Returnată"])}</label><label>Data de la<input type="date" name="data_de_la"></label><label>Data până la<input type="date" name="data_pana"></label><button>Descarcă Excel (.xlsx)</button></form>'
                return self.send_page(layout('Rapoarte','<h1>Rapoarte Excel</h1><p>Export complet: fișe, toate câmpurile de stațiune, speciile, lucrările, solurile și observațiile istorice, dacă există. Foaia «Fise_complete» reunește toate informațiile unei fișe pe un singur rând; celelalte foi permit analiza detaliată. Implicit se exportă toate statutele; poți selecta doar fișele aprobate.</p>'+filters,u))
            if route=='/export-xlsx':
                data=parse_qs(p.query)
                mid=sqlint(data.get('primarie',['0'])[0]);status=data.get('status',['Toate'])[0]
                date_from=data.get('data_de_la',[''])[0]; date_to=data.get('data_pana',[''])[0]
                if mid and not can_municipality(c,u,mid):return self.error('Acces interzis',403)
                if status not in ('Aprobate','Toate','Ciornă','Transmisă','Returnată'):return self.error('Filtru statut invalid')
                where=["(?='admin' OR EXISTS (SELECT 1 FROM user_municipalities a JOIN users usr ON usr.id=a.user_id WHERE a.municipality_id=m.id AND usr.username=?))"]
                args=[u['role'],u['name']]
                if mid: where.append('m.id=?');args.append(mid)
                if status=='Aprobate':where.append("f.status='Aprobată'")
                elif status!='Toate':where.append('f.status=?');args.append(status)
                if date_from:where.append('f.inventory_date>=?');args.append(date_from)
                if date_to:where.append('f.inventory_date<=?');args.append(date_to)
                sql='''SELECT m.name AS primarie,m.district,u.code AS ua,u.name AS denumire_ua,
                    u.area AS suprafata_ha,f.* FROM forms f
                    JOIN units u ON u.id=f.unit_id JOIN municipalities m ON m.id=u.municipality_id WHERE '''+' AND '.join(where)
                forms=c.execute(sql+' ORDER BY m.name,u.code,f.inventory_date,f.id',args).fetchall()
                # A complete row per field sheet. No lost values or averaged surface areas.
                metadata=[('primarie','Primărie'),('district','Raion'),('ua','UA'),('denumire_ua','Denumire sector'),('suprafata_ha','Suprafață UA (ha)')]
                columns=[('id','ID fișă'),('inventory_date','Data inventarierii'),('author','Specialist'),
                    ('status','Statut'),('locality','Trup / localitate'),('altitude_min','Altitudine minimă (m)'),
                    ('altitude_max','Altitudine maximă (m)'),('slope','Înclinare (grade)'),('aspect','Expoziție'),
                    ('relief','Formă de relief'),('previous_management','Gospodărirea anterioară'),
                    ('functional_group','Grupa funcțională'),('land_use','Categoria de folosință'),
                    ('watering_source','Sursa de adăpare'),('landslide_ha','Alunecări (ha)'),
                    ('erosion_ha','Eroziune (ha)'),('moisture_ha','Exces de umiditate (ha)'),
                    ('stones_ha','Petriș (ha)'),('grass_cover_pct','Acoperire ierboasă (%)'),
                    ('ruderal_pct','Vegetație ruderală (%)'),('woody_cover_pct','Vegetație lemnoasă (%)'),
                    ('pasture_type_code','Cod tip pajiște'),('pasture_type_name','Tip pajiște'),
                    ('notes','Observații'),('created_at','Creat la'),('updated_at','Actualizat la'),
                    ('created_by','Creat de'),('assigned_to','Cont specialist atribuit'),('decision_by','Decizie de'),('decision_at','Data deciziei'),
                    ('return_reason','Motivul returnării'),('approval_mode','Metoda aprobării')]
                # Include future added columns too, without dropping any saved form values.
                selected_field_keys={k for k,_ in metadata+columns}
                additional_fields=[(name,name.replace('_',' ').capitalize()) for name in forms[0].keys()
                    if name not in selected_field_keys] if forms else []
                full_columns=metadata+columns+additional_fields
                rows1=[[label for _,label in full_columns]]+[[r[key] for key,_ in full_columns] for r in forms]
                selected_ids=[r['id'] for r in forms]
                # Use selected form IDs to apply EXACTLY the same status/date/access filters in all sheets.
                rows2=[['ID fișă','Primărie','UA','Statut','Grup','Specie științifică','Denumire populară','Participare (%)','ID nomenclator']]
                rows3=[['ID fișă','Primărie','UA','Statut','Lucrare','Ani execuție','Suprafață (ha)','Observații']]
                by_id={r['id']:r for r in forms}
                if selected_ids:
                    placeholders=','.join('?' for _ in selected_ids)
                    for r in c.execute('SELECT * FROM species WHERE form_id IN ('+placeholders+') ORDER BY form_id,id',selected_ids):
                        f=by_id[r['form_id']]
                        rows2.append([r['form_id'],f['primarie'],f['ua'],f['status'],r['category'],
                            r['scientific_name'],r['common_name'],r['participation_pct'],r['catalog_id']])
                    for r in c.execute('SELECT * FROM works WHERE form_id IN ('+placeholders+') ORDER BY form_id,id',selected_ids):
                        f=by_id[r['form_id']]
                        rows3.append([r['form_id'],f['primarie'],f['ua'],f['status'],r['title'],r['years'],r['area_ha'],r['notes']])
                # One export row per completed form, including all child observations.
                # The normalized sheets below remain authoritative when a form has many species/works.
                joined_species={fid:[] for fid in selected_ids}
                joined_works={fid:[] for fid in selected_ids}
                grouped_species={fid:{'Graminee':[],'Fabacee':[],
                    'Alte familii botanice':[],'Vegetație lemnoasă':[]} for fid in selected_ids}
                for record in rows2[1:]:
                    fid,prim,ua,stat,cat,scientific,common,pct,catalog=record
                    name=str(scientific or '')
                    label=name+(f' ({common})' if common else '')+(f' — {pct}%' if pct is not None else '')
                    joined_species[fid].append(f'{cat}: {label}')
                    grouped_species[fid].setdefault(cat,[]).append(label)
                for record in rows3[1:]:
                    fid,prim,ua,stat,title,years,area,notes=record
                    line=str(title or '')+(f' | ani: {years}' if years else '')
                    line+=(f' | ha: {area}' if area is not None else '')
                    line+=(f' | {notes}' if notes else '')
                    joined_works[fid].append(line)
                joined_soils={fid:[] for fid in selected_ids}
                joined_history={fid:[] for fid in selected_ids}
                has_soils=bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='soils'").fetchone())
                has_history=bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='legacy_data'").fetchone())
                if selected_ids and has_soils:
                    placeholders=','.join('?' for _ in selected_ids)
                    for record in c.execute('SELECT * FROM soils WHERE form_id IN ('+placeholders+') ORDER BY form_id,id',selected_ids):
                        joined_soils[record['form_id']].append(
                            f"{record['soil_code']} | {record['area_ha']} ha | {record['percent']}%")
                if selected_ids and has_history:
                    placeholders=','.join('?' for _ in selected_ids)
                    for record in c.execute('SELECT * FROM legacy_data WHERE form_id IN ('+placeholders+') ORDER BY form_id',selected_ids):
                        for field_key,value in json.loads(record['payload_json']).items():
                            joined_history[record['form_id']].append(f'{field_key}: {value}')
                extra_headers=['Specii – Graminee','Specii – Fabacee','Specii – alte familii',
                    'Specii – vegetație lemnoasă','Specii – toate observațiile',
                    'Lucrări – toate observațiile','Soluri – toate tipurile',
                    'Date istorice suplimentare']
                complete_rows=[rows1[0]+extra_headers]
                for record,base_values in zip(forms,rows1[1:]):
                    fid=record['id']; groups=grouped_species[fid]
                    complete_rows.append(base_values+[
                        '; '.join(groups['Graminee']),
                        '; '.join(groups['Fabacee']),
                        '; '.join(groups['Alte familii botanice']),
                        '; '.join(groups['Vegetație lemnoasă']),
                        '; '.join(joined_species[fid]),
                        '; '.join(joined_works[fid]),
                        '; '.join(joined_soils[fid]),
                        '; '.join(joined_history[fid])])
                worksheets=[('Fise_complete',complete_rows),('Fise',rows1),
                    ('Specii',rows2),('Lucrari',rows3)]
                # Include UA without any forms; this is the complete municipality inventory.
                unit_sql='''SELECT m.name AS primarie,m.district,u.code,u.name,u.area,
                    (SELECT COUNT(*) FROM forms f WHERE f.unit_id=u.id) AS fise
                    FROM units u JOIN municipalities m ON m.id=u.municipality_id
                    WHERE (?='admin' OR EXISTS (SELECT 1 FROM user_municipalities a
                        JOIN users usr ON usr.id=a.user_id WHERE a.municipality_id=m.id AND usr.username=?))'''
                unit_args=[u['role'],u['name']]
                if mid: unit_sql+=' AND m.id=?';unit_args.append(mid)
                unit_rows=c.execute(unit_sql+' ORDER BY m.name,u.code',unit_args).fetchall()
                ua_rows=[['Primărie','Raion','Cod UA','Denumirea sectorului','Suprafață (ha)','Fișe existente']]
                ua_rows += [[unit[k] for k in ('primarie','district','code','name','area','fise')] for unit in unit_rows]
                worksheets.append(('UA',ua_rows))
                soils=[['ID fișă','Primărie','UA','Cod tip sol','Suprafață (ha)','Procent (%)']]
                if selected_ids and has_soils:
                    placeholders=','.join('?' for _ in selected_ids)
                    for r in c.execute('SELECT * FROM soils WHERE form_id IN ('+placeholders+') ORDER BY form_id,id',selected_ids):
                        f=by_id[r['form_id']]
                        soils.append([r['form_id'],f['primarie'],f['ua'],r['soil_code'],r['area_ha'],r['percent']])
                worksheets.append(('Soluri',soils))
                hist=[['ID fișă','Primărie','UA','Câmp istoric','Valoare']]
                if selected_ids and has_history:
                    placeholders=','.join('?' for _ in selected_ids)
                    for r in c.execute('SELECT * FROM legacy_data WHERE form_id IN ('+placeholders+') ORDER BY form_id',selected_ids):
                        f=by_id[r['form_id']]
                        for k,v in json.loads(r['payload_json']).items():
                            hist.append([r['form_id'],f['primarie'],f['ua'],k,v])
                worksheets.append(('Date_istorice',hist))
                return self.send_page(make_xlsx(worksheets),
                    content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    attachment=('GeoPajisti_primarie_'+str(mid)+'.xlsx' if mid else 'GeoPajisti_toate_primariile.xlsx'))
            if route.startswith('/export'):
                # Retain CSV routes for older workflows, but enforce municipality access.
                data=parse_qs(p.query);municipality=sqlint(data.get('primarie',['0'])[0]);
                if municipality and not can_municipality(c,u,municipality):return self.error('Acces interzis',403)
                where=' WHERE '+("m.id=? AND " if municipality else "")+"(?='admin' OR EXISTS (SELECT 1 FROM user_municipalities a JOIN users usr ON usr.id=a.user_id WHERE a.municipality_id=m.id AND usr.username=?))"
                args=((municipality,) if municipality else ())+(u['role'],u['name'])
                out=io.StringIO();writer=csv.writer(out)
                if route=='/export':
                    writer.writerow(['Primărie','Raion','UA','Suprafață UA ha','Nr fișă','Data','Specialist','Status','Altitudine min','Altitudine max','Pantă','Expoziție','Acoperire ierboasă %','Eroziune ha','Tip pajiște cod','Tip pajiște','Observații'])
                    rows=c.execute('SELECT m.name,m.district,u.code,u.area,f.* FROM forms f JOIN units u ON u.id=f.unit_id JOIN municipalities m ON m.id=u.municipality_id'+where+' ORDER BY m.name,u.code,f.inventory_date',args)
                    for x in rows: writer.writerow([x[k] for k in ('name','district','code','area','id','inventory_date','author','status','altitude_min','altitude_max','slope','aspect','grass_cover_pct','erosion_ha','pasture_type_code','pasture_type_name','notes')])
                elif route=='/export-specii':
                    writer.writerow(['Primărie','UA','Fișa','Categorie','Specia științifică','Denumire populară','Participare %'])
                    rows=c.execute('SELECT m.name,u.code,s.* FROM species s JOIN forms f ON f.id=s.form_id JOIN units u ON u.id=f.unit_id JOIN municipalities m ON m.id=u.municipality_id'+where+' ORDER BY m.name,u.code,s.id',args)
                    for x in rows:writer.writerow([x[k] for k in ('name','code','form_id','category','scientific_name','common_name','participation_pct')])
                elif route=='/export-lucrari':
                    writer.writerow(['Primărie','UA','Fișa','Lucrare','Ani','Suprafață ha','Observații'])
                    rows=c.execute('SELECT m.name,u.code,w.* FROM works w JOIN forms f ON f.id=w.form_id JOIN units u ON u.id=f.unit_id JOIN municipalities m ON m.id=u.municipality_id'+where+' ORDER BY m.name,u.code,w.id',args)
                    for x in rows:writer.writerow([x[k] for k in ('name','code','form_id','title','years','area_ha','notes')])
                else:return self.error('Rută necunoscută',404)
                return self.send_page('\ufeff'+out.getvalue(),content_type='text/csv; charset=utf-8',attachment=route.strip('/')+'.csv')
        self.error('Pagina nu există',404)
    def historical_details(self,fid):
        with conn() as db:
            available=db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='legacy_data'").fetchone()
            if not available:return ''
            obj=db.execute('SELECT * FROM legacy_data WHERE form_id=?',(fid,)).fetchone()
            soils=db.execute('SELECT * FROM soils WHERE form_id=?',(fid,)).fetchall() if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='soils'").fetchone() else []
        if not obj:return ''
        data=json.loads(obj['payload_json'])
        labels={'versant_ha':'Versant (ha)','versant_pct':'Versant (%)','lunca_ha':'Luncă (ha)','lunca_pct':'Luncă (%)','alte_forme_ha':'Alte forme (ha)','alte_forme_pct':'Alte forme (%)','alunecari_pct':'Alunecări (%)','eroziune_pct':'Eroziune (%)','exces_umiditate_pct':'Exces umiditate (%)','pietris_pct':'Petriș (%)','acoperire_ierbos_ha':'Covor ierbos (ha)','goluri_ha':'Goluri (ha)','goluri_pct':'Goluri (%)','musuroaie_ha':'Mușuroaie (ha)','musuroaie_pct':'Mușuroaie (%)','vegetatie_ruderala_ha':'Ruderală (ha)','vegetatie_lemnoasa_ha':'Lemnoasă (ha)','total_graminee_pct':'Graminee total (%)','total_fabacee_pct':'Fabacee total (%)','total_alte_familii_pct':'Alte familii total (%)'}
        rows=''.join(f'<tr><th>{esc(label)}</th><td>{esc(data.get(key) or "—")}</td></tr>' for key,label in labels.items())
        sol=''.join(f'<tr><td>{esc(x["soil_code"])}</td><td>{esc(x["area_ha"])}</td><td>{esc(x["percent"])}</td></tr>' for x in soils)
        return f'<details class="card"><summary>Date istorice suplimentare ({esc(obj["source_sheet"])}, UA originală {esc(obj["original_ua"])})</summary><p class="muted">Valorile sunt păstrate conform sursei și nu sunt editabile.</p><table>{rows}</table><h3>Tipuri de sol</h3><table><tr><th>Cod</th><th>ha</th><th>%</th></tr>{sol}</table></details>'

    def edit_form(self,r,species,works):
        editable=can_edit(self.user(),r); fid=r['id']
        def f(name,label,typ='text'):return field(name,label,r[name],typ,'any' if typ=='number' else None)
        parts=f'<a href="/ua/{r["unit_id"]}">← UA {esc(r["code"])}</a><h1>Fișă #{fid} · {esc(r["municipality"])} / UA {esc(r["code"])}</h1><p>Stare: <strong>{esc(r["status"])}</strong> · Suprafața UA: {esc(r["area"])} ha</p><div class="actions"><a class="btn secondary" href="/fisa/{fid}?print" target="_blank">Fișă pentru imprimare / PDF</a></div>'
        parts+=f'<form method="post" action="/fisa/save" class="card">{self.hidden()}<input type="hidden" name="id" value="{fid}"><h2>Date generale</h2><div class="grid">{f("inventory_date","Data inventarierii","date")}{(f("author","Specialist") if self.user()["role"]=="admin" else field("specialist_display","Specialist",r["author"]).replace("name=\"specialist_display\"", "name=\"specialist_display\" readonly"))}{f("locality","Trup / localitate")}{f("previous_management","Gospodărirea anterioară")}{f("functional_group","Grupa funcțională")}{f("land_use","Categoria de folosință")}{f("watering_source","Sursa de adăpare")}</div><h2>Descrierea stațiunii</h2><div class="grid">{f("altitude_min","Altitudine minimă m","number")}{f("altitude_max","Altitudine maximă m","number")}{f("relief","Relief")}{f("slope","Înclinare grade","number")}{f("aspect","Expoziție")}{f("landslide_ha","Alunecări ha","number")}{f("erosion_ha","Eroziune ha","number")}{f("moisture_ha","Exces umiditate ha","number")}{f("stones_ha","Petriș ha","number")}{f("grass_cover_pct","Acoperire covor ierbos %","number")}{f("ruderal_pct","Vegetație ruderală %","number")}{f("woody_cover_pct","Vegetație lemnoasă %","number")}</div><h2>Tipul pajiștii</h2><div class="grid">{f("pasture_type_code","Cod tip")}{f("pasture_type_name","Denumire tip")}</div><label>Observații<textarea name="notes" rows="4">{esc(r["notes"])}</textarea></label>'
        parts+=self.historical_details(fid)
        if editable:parts+='<button>Salvează fișa</button>'
        parts+='</form>'
        parts+='<div class="card"><h2>Specii înregistrate</h2><table><tr><th>Grup</th><th>Specie</th><th>Populară</th><th>%</th></tr>'+''.join(f'<tr><td>{esc(x["category"])}</td><td>{esc(x["scientific_name"])}</td><td>{esc(x["common_name"])}</td><td>{esc(x["participation_pct"])}</td></tr>' for x in species)+'</table></div>'
        if editable:
            with conn() as sc:
                catalog=sc.execute('SELECT id,scientific_name,common_name FROM species_catalog WHERE active=1 ORDER BY scientific_name').fetchall()
            opts='<option value="0">— Introducere manuală —</option>'+''.join(f'<option value="{x["id"]}">{esc(x["scientific_name"])} ({esc(x["common_name"])})</option>' for x in catalog)
            parts+=f'<form method="post" action="/specie/new" class="card">{self.hidden()}<input type="hidden" name="form_id" value="{fid}"><h3>Adaugă specie</h3><label>Din banca de specii<select name="catalog_id">{opts}</select></label><p class="muted">Dacă alegi o specie din bancă, denumirea și grupa se preiau automat. Altfel completează manual câmpurile.</p><div class="grid"><label>Grup (manual){select("category",["Graminee","Fabacee","Alte familii botanice","Vegetație lemnoasă"])}</label>{field("scientific_name","Denumire științifică (manual)")}{field("common_name","Denumire populară (manual)")}{field("participation_pct","Participare %","number","any")}</div><button>Adaugă specie</button></form>'
        parts+='<div class="card"><h2>Lucrări propuse</h2><table><tr><th>Lucrare</th><th>Ani</th><th>ha</th><th>Observații</th></tr>'+''.join(f'<tr><td>{esc(x["title"])}</td><td>{esc(x["years"])}</td><td>{esc(x["area_ha"])}</td><td>{esc(x["notes"])}</td></tr>' for x in works)+'</table></div>'
        if editable:
            parts+=f'<form method="post" action="/lucrare/new" class="card">{self.hidden()}<input type="hidden" name="form_id" value="{fid}"><h3>Adaugă lucrare</h3><div class="grid">{field("title","Denumire lucrare")}{field("years","Ani execuție")}{field("area_ha","Suprafață ha","number","any")}{field("notes","Observații")}</div><button>Adaugă lucrare</button></form>'
            parts+=f'<form method="post" action="/fisa/status" class="card">{self.hidden()}<input type="hidden" name="id" value="{fid}"><input type="hidden" name="status" value="Aprobată"><h3>Finalizarea fișei</h3><p class="muted">Prin trimitere, fișa primește automat statutul «Aprobată» și nu mai poate fi editată până la redeschiderea de către administrator.</p><button>Trimite fișa · aprobare automată</button></form>'
       
        if self.user()['role']=='aprobator' and r['status'] in ('Transmisă','Verificată'):
            parts+=f'<form method="post" action="/fisa/status" class="card">{self.hidden()}<input type="hidden" name="id" value="{fid}"><h3>Decizia aprobatorului</h3><label>Observații pentru corectare<textarea name="reason" rows="3"></textarea></label><button name="status" value="Aprobată">Aprobă fișa</button> <button name="status" value="Returnată" style="background:#aa5a18">Returnează pentru corectare</button></form>'
        if r['status']=='Returnată' and r['return_reason']:
            parts+=f'<div class="card"><h3>Motivul returnării</h3><p>{esc(r["return_reason"])}</p></div>'
        if self.user()['role']=='admin' and r['status']=='Aprobată':
            parts += (
                '<form method="post" action="/fisa/reopen" class="card no-print" '
                'onsubmit="return confirm(\'Redeschizi această fișă aprobată pentru corectare? Modificările vor necesita o nouă trimitere.\')">'
                + self.hidden()
                + f'<input type="hidden" name="id" value="{fid}">'
                + '<h3>Corectarea unei fișe aprobate</h3>'
                + '<p class="muted">Revenirea în starea „Returnată” păstrează istoricul aprobării precedente.</p>'
                + '<button type="submit" style="background:#a85c14">Modifică fișa aprobată</button></form>'
            )
        if self.user() and self.user()['role'] == 'admin':
            parts += (
                '<form method="post" action="/fisa/delete" ' 
                'class="card no-print" '
                'onsubmit="return confirm(\'Sigur ștergi definitiv această fișă?\')">'
                + self.hidden()
                + f'<input type="hidden" name="id" value="{fid}">'
                + '<button type="submit" style="background:#b42318">'
                'Șterge fișa</button></form>'
            )
        return parts
    def print_form(self,r,species,works,offline=False):
        # A4 landscape compact template with scaling for long inventories.
        def v(key):
            value=r[key]
            return esc(value if value not in ('',None) else '—')
        def cell(key,label):
            return f'<div class="field"><b>{esc(label)}:</b> {v(key)}</div>'
        general=[('municipality','Primărie'),('code','UA'),('area','Suprafață UA (ha)'),
            ('inventory_date','Data inventarierii'),('author','Specialist'),('status','Statut'),
            ('locality','Trup / localitate'),('previous_management','Gospodărirea anterioară'),
            ('functional_group','Grupa funcțională'),('land_use','Categoria de folosință'),
            ('watering_source','Sursa de adăpare')]
        station=[('altitude_min','Altitudine minimă (m)'),('altitude_max','Altitudine maximă (m)'),
            ('slope','Înclinare (grade)'),('aspect','Expoziție'),('relief','Relief'),
            ('landslide_ha','Alunecări (ha)'),('erosion_ha','Eroziune (ha)'),
            ('moisture_ha','Exces umiditate (ha)'),('stones_ha','Petriș (ha)'),
            ('grass_cover_pct','Acoperire ierboasă (%)'),('ruderal_pct','Ruderală (%)'),
            ('woody_cover_pct','Vegetație lemnoasă (%)')]
        def grid(items):return '<div class="data-grid">'+''.join(cell(k,label) for k,label in items)+'</div>'
        # Keep every species and work in the printed sheet.
        sp=''.join(f'<tr><td>{esc(x["category"])}</td><td><i>{esc(x["scientific_name"])}</i></td>'
            f'<td>{esc(x["common_name"])}</td><td>{esc(x["participation_pct"])}</td></tr>' for x in species)
        wo=''.join(f'<tr><td>{esc(x["title"])}</td><td>{esc(x["years"])}</td>'
            f'<td>{esc(x["area_ha"])}</td><td>{esc(x["notes"])}</td></tr>' for x in works)
        extra=''
        with conn() as c:
            if c.execute("SELECT 1 FROM sqlite_master WHERE name='legacy_data'").fetchone():
                obj=c.execute('SELECT * FROM legacy_data WHERE form_id=?',(r['id'],)).fetchone()
                if obj:
                    data=json.loads(obj['payload_json'])
                    extra+='<h2>Date istorice suplimentare</h2><div class="data-grid">'+''.join(
                        f'<div class="field"><b>{esc(k.replace("_"," "))}:</b> {esc(value)}</div>'
                        for k,value in data.items() if value not in (None,''))+'</div>'
            if c.execute("SELECT 1 FROM sqlite_master WHERE name='soils'").fetchone():
                soils=c.execute('SELECT * FROM soils WHERE form_id=?',(r['id'],)).fetchall()
                if soils:
                    extra+='<h2>Tipuri de sol</h2><table><tr><th>Cod sol</th><th>Suprafață (ha)</th><th>%</th></tr>'+''.join(
                        f'<tr><td>{esc(x["soil_code"])}</td><td>{esc(x["area_ha"])}</td><td>{esc(x["percent"])}</td></tr>' for x in soils)+'</table>'
        toolbar=('<div class="toolbar"><button onclick="window.print()">Imprimă / salvează PDF – A4</button>'
                 +('' if offline else f' <a href="/fisa/{r["id"]}">Înapoi la fișă</a>')+'</div>')
        content=(toolbar
                 +'<main id="print-sheet"><h1>FIȘĂ DE DESCRIERE A PAJIȘTII</h1>'
                 +f'<div class="sub">Fișa nr. {r["id"]} · {v("municipality")} / UA {v("code")}</div>'
                 +'<h2>Date generale</h2>'+grid(general)
                 +'<h2>Descrierea stațiunii</h2>'+grid(station)
                 +'<h2>Tipul pajiștii</h2>'+grid([('pasture_type_code','Cod tip'),('pasture_type_name','Denumire')])
                 +'<h2>Compoziția floristică și vegetația lemnoasă</h2>'
                 +'<table><tr><th>Grup</th><th>Specie</th><th>Denumire populară</th><th>Participare (%)</th></tr>'
                 +(sp or '<tr><td colspan="4">Nu sunt specii introduse</td></tr>')+'</table>'
                 +'<h2>Lucrări propuse</h2><table><tr><th>Lucrare</th><th>Ani</th><th>Suprafață (ha)</th><th>Observații</th></tr>'
                 +(wo or '<tr><td colspan="4">Nu sunt lucrări introduse</td></tr>')+'</table>'
                 +extra+'<h2>Observații și validare</h2><div class="data-grid">'
                 +cell('notes','Observații')+cell('created_by','Creat de')
                 +cell('decision_by','Statut actualizat de')+cell('decision_at','Data deciziei')
                 +cell('return_reason','Motiv returnare')+cell('approval_mode','Metoda aprobării')+'</div></main>')
        css='''<!doctype html><html lang="ro"><head><meta charset="utf-8"><title>Fișă de teren A4</title>
<style>
@page{size:A4 landscape;margin:7mm}
*{box-sizing:border-box}body{margin:0;background:#e9eee9;font:12px Arial,sans-serif;color:#192f25}
.toolbar{padding:12px;text-align:center}.toolbar button{background:#206f4e;color:white;padding:10px;border:0;border-radius:5px;cursor:pointer}
#print-sheet{width:283mm;margin:0 auto;padding:5mm;background:white;box-shadow:0 2px 10px #ccc}
h1{text-align:center;font-size:17px;margin:0 0 3px}.sub{text-align:center;font-size:10px;margin-bottom:5px}
h2{font-size:12px;background:#e8efe9;padding:2px 5px;margin:5px 0 2px;border-left:3px solid #32664a}
.data-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:2px 7px}
.field{font-size:11px;padding:1px 2px;border-bottom:1px solid #e8ece8;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{font-size:10.5px;padding:2px 3px;border:1px solid #cbd7cc;text-align:left;overflow-wrap:anywhere}
th{background:#e8efe9}
@media print{body{background:white}.toolbar{display:none!important}
 #print-sheet{position:absolute;top:0;left:0;margin:0;padding:0;width:283mm;
  max-height:196mm;box-shadow:none;transform-origin:top left;page-break-inside:avoid}
 body{overflow:hidden}
 *{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style></head><body>'''
        # Print preview scaling: target printable page is ~283 x 196 mm with 7 mm margins.
        # For exceptionally long records text may become too small: export complete Excel too.
        fit='''<script>
function fitA4(){const s=document.getElementById('print-sheet');
 s.style.transform=''; s.style.width='283mm';
 const maxHeight=196*96/25.4;
 const ratio=Math.min(1,maxHeight/s.scrollHeight);
 s.style.transform='scale('+ratio+')';
}
window.addEventListener('beforeprint',fitA4);
window.addEventListener('load',fitA4);
</script>'''
        return css+content+fit+'</body></html>'
    def do_POST(self):
        u=self.user();route=urlparse(self.path).path
        try:f=self.data()
        except ValueError as e:return self.error(str(e),413)
        if route=='/login':
            with conn() as c: user=c.execute('SELECT * FROM users WHERE username=?',(f.get('username',''),)).fetchone()
            good=False
            if user:
                d=hashlib.pbkdf2_hmac('sha256',f.get('password','').encode(),bytes.fromhex(user['salt']),210000).hex()
                good=hmac.compare_digest(d,user['password_hash'])
            if not good:return self.error('Utilizator sau parolă incorectă',401)
            token=secrets.token_urlsafe(32);SESSIONS[token]={'name':user['username'],'role':user['role'],'csrf':secrets.token_urlsafe(24)}
            secure='; Secure' if os.environ.get('COOKIE_SECURE')=='1' else ''
            return self.redirect('/',f'gp_session={token}; HttpOnly; SameSite=Lax; Path=/{secure}')
        if not u:return self.redirect('/login')
        if not self.csrf(f):return self.error('Sesiune invalidă (CSRF)',403)
        now=datetime.utcnow().isoformat(timespec='seconds')+'Z'
        try:
            with LOCK,conn() as c:
                if route=='/utilizatori/nume':
                    if u['role']!='admin':return self.error('Acces rezervat administratorului',403)
                    uid=sqlint(f.get('user_id'))
                    if not c.execute('SELECT 1 FROM users WHERE id=?',(uid,)).fetchone():return self.error('Utilizator inexistent',404)
                    prenume=f.get('first_name','').strip()
                    nume=f.get('last_name','').strip()
                    if len(prenume)>100 or len(nume)>100:return self.error('Nume prea lung',400)
                    c.execute('UPDATE users SET first_name=?,last_name=? WHERE id=?',(prenume,nume,uid))
                    dest='/utilizatori'
                elif route=='/utilizatori/new':
                    if u['role']!='admin':return self.error('Acces interzis',403)
                    username=f.get('username','').strip();password=f.get('password','');role=f.get('role','');first=f.get('first_name','').strip();last=f.get('last_name','').strip()
                    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}',username):return self.error('Utilizator: 3–40 de caractere (litere, cifre, _, . sau -)')
                    if len(password)<12:return self.error('Parolă prea scurtă (minimum 12 caractere)')
                    if role not in ROLES:return self.error('Rol invalid')
                    if not first or not last or len(first)>100 or len(last)>100:return self.error('Introdu prenumele și numele specialistului (maximum 100 de caractere fiecare)')
                    salt,digest=pw_hash(password)
                    c.execute('INSERT INTO users(username,salt,password_hash,role,first_name,last_name) VALUES(?,?,?,?,?,?)',(username,salt,digest,role,first,last));dest='/utilizatori'
                elif route=='/utilizatori/delete':
                    if u['role']!='admin':return self.error('Acces rezervat administratorului',403)
                    uid=sqlint(f.get('user_id'))
                    target=c.execute('SELECT username,role FROM users WHERE id=?',(uid,)).fetchone()
                    if not target:return self.error('Utilizatorul nu există',404)
                    if target['username']==u['name']:return self.error('Nu îți poți șterge propriul cont',403)
                    if target['role']=='admin':
                        admins=c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
                        if admins<=1:return self.error('Ultimul administrator nu poate fi șters',403)
                    # Fișele, observațiile și auditul sunt păstrate; se revocă sesiunile.
                    c.execute('DELETE FROM users WHERE id=?',(uid,))
                    for token,session in list(SESSIONS.items()):
                        if session['name']==target['username']:SESSIONS.pop(token,None)
                    dest='/utilizatori'
                elif route=='/utilizatori/acces':
                    if u['role']!='admin':return self.error('Acces interzis',403)
                    uid=sqlint(f.get('user_id'));mid=sqlint(f.get('municipality_id'));action=f.get('action')
                    usr=c.execute('SELECT role FROM users WHERE id=?',(uid,)).fetchone()
                    if not usr or usr['role']=='admin' or not c.execute('SELECT 1 FROM municipalities WHERE id=?',(mid,)).fetchone():return self.error('Selecție invalidă',400)
                    if action=='acorda':c.execute('INSERT OR IGNORE INTO user_municipalities(user_id,municipality_id) VALUES(?,?)',(uid,mid))
                    elif action=='revoca':c.execute('DELETE FROM user_municipalities WHERE user_id=? AND municipality_id=?',(uid,mid))
                    else:return self.error('Acțiune invalidă',400)
                    dest='/utilizatori'
                elif route=='/catalog/new':
                    if u['role']!='admin':return self.error('Acces interzis',403)
                    name=f.get('scientific_name','').strip();category=f.get('category')
                    if len(name)<3 or category not in ('Graminee','Fabacee','Alte familii botanice','Vegetație lemnoasă'):return self.error('Specie sau grup invalid')
                    c.execute('INSERT INTO species_catalog(scientific_name,common_name,family,category,source) VALUES(?,?,?,?,?)',(name,f.get('common_name','').strip(),f.get('family','').strip(),category,f.get('source','').strip()));dest='/specii'
                elif route=='/primarii':
                    if u['role']!='admin':return self.error('Acces interzis',403)
                    if not f.get('name','').strip():return self.error('Denumirea primăriei este obligatorie')
                    cursor=c.execute('INSERT INTO municipalities(name,district) VALUES (?,?)',(f['name'].strip(),f.get('district','').strip()));dest=f'/primarie/{cursor.lastrowid}'
                elif route=='/ua/new':
                    if u['role']!='admin':return self.error('Acces interzis',403)
                    if not f.get('code','').strip():return self.error('Codul UA este obligatoriu')
                    cursor=c.execute('INSERT INTO units(municipality_id,code,name,area) VALUES (?,?,?,?)',(sqlint(f.get('municipality_id')),f['code'].strip(),f.get('name',''),num(f.get('area')) or 0));dest=f'/ua/{cursor.lastrowid}'
                
                elif route == '/ua/delete':
                    if u['role'] != 'admin':
                        return self.error(
                            'Numai administratorul poate șterge UA', 403
                        )

                    uid = sqlint(f.get('id'))

                    row = c.execute(
                        'SELECT municipality_id FROM units WHERE id=?',
                        (uid,)
                    ).fetchone()

                    if row is None:
                        return self.error('UA nu există', 404)

                    count = c.execute(
                        'SELECT COUNT(*) FROM forms WHERE unit_id=?',
                        (uid,)
                    ).fetchone()[0]

                    if count > 0:
                        return self.error(
                            'UA conține fișe. Șterge mai întâi fișele.'
                        )

                    c.execute(
                        'DELETE FROM units WHERE id=?', (uid,)
                    )

                    dest = f'/primarie/{row["municipality_id"]}'
                elif route=='/fisa/new':
                    if u['role'] not in ('admin','specialist'):return self.error('Acces interzis',403)
                    uid=sqlint(f.get('unit_id'))
                    if not unit_access(c,u,uid):return self.error('Nu ai acces la UA',403)
                    author_usr=u['name']
                    if u['role']=='admin':
                        author_usr=f.get('author_username','')
                        chosen=c.execute('''SELECT usr.* FROM users usr LEFT JOIN user_municipalities a
                            ON a.user_id=usr.id AND a.municipality_id=(SELECT municipality_id FROM units WHERE id=?)
                            WHERE usr.username=? AND (usr.username=? OR (usr.role='specialist' AND a.municipality_id IS NOT NULL))''',
                            (uid,author_usr,u['name'])).fetchone()
                        if not chosen:return self.error('Selectează un specialist autorizat pentru această primărie',403)
                    else:
                        chosen=c.execute('SELECT * FROM users WHERE username=?',(u['name'],)).fetchone()
                    author=full_name(chosen) if chosen else u['name']
                    cursor=c.execute('INSERT INTO forms(unit_id,inventory_date,author,created_at,updated_at,created_by,assigned_to) VALUES (?,?,?,?,?,?,?)',
                        (uid,f.get('inventory_date',''),author,now,now,u['name'],author_usr))
                    dest=f'/fisa/{cursor.lastrowid}'
                    record_form_change(c,cursor.lastrowid,'Fișă creată',u['name'],now,None)
                elif route=='/fisa/save':
                    fid=sqlint(f.get('id'))
                    r=c.execute('SELECT * FROM forms WHERE id=?',(fid,)).fetchone()
                    if not r or not form_access(c,u,fid) or not can_edit(u,r):return self.error('Nu ai dreptul să editezi această fișă',403)
                    textfields=['inventory_date','author','locality','previous_management','functional_group','land_use','watering_source','relief','aspect','pasture_type_code','pasture_type_name','notes']
                    numeric=['altitude_min','altitude_max','slope','landslide_ha','erosion_ha','moisture_ha','stones_ha','grass_cover_pct','ruderal_pct','woody_cover_pct']
                    fields=textfields+numeric+['updated_at']
                    values=[(r['author'] if x=='author' and u['role']=='specialist' else f.get(x,'').strip()) for x in textfields]+[num(f.get(x,'')) for x in numeric]+[now]
                    for col in ['grass_cover_pct','ruderal_pct','woody_cover_pct']:
                        n=num(f.get(col));
                        if n is not None and not 0<=n<=100:return self.error('Procentele trebuie să fie între 0 și 100')
                    before=form_snapshot(c,fid)
                    c.execute('UPDATE forms SET '+','.join(x+'=?' for x in fields)+' WHERE id=?',values+[fid]);dest=f'/fisa/{fid}'
                    record_form_change(c,fid,'Fișă modificată',u['name'],now,before)
                elif route=='/specie/new':
                    fid=sqlint(f.get('form_id'));r=c.execute('SELECT * FROM forms WHERE id=?',(fid,)).fetchone()
                    if not r or not form_access(c,u,fid) or not can_edit(u,r):return self.error('Fișa nu poate fi editată',403)
                    catalog_id=sqlint(f.get('catalog_id'))
                    if catalog_id:
                        item=c.execute('SELECT * FROM species_catalog WHERE id=? AND active=1',(catalog_id,)).fetchone()
                        if not item:return self.error('Specia nu există în bancă')
                        sci=item['scientific_name'];common=item['common_name'];category=item['category']
                    else:
                        sci=f.get('scientific_name','').strip();common=f.get('common_name','').strip();category=f.get('category','')
                        if not sci:return self.error('Specia este obligatorie')
                    pct=num(f.get('participation_pct'))
                    if pct is not None and not 0<=pct<=100:return self.error('Procent invalid')
                    before=form_snapshot(c,fid)
                    c.execute('INSERT INTO species(form_id,category,scientific_name,common_name,participation_pct,catalog_id) VALUES (?,?,?,?,?,?)',(fid,category,sci,common,pct,catalog_id or None));dest=f'/fisa/{fid}'
                    record_form_change(c,fid,'Specie adăugată',u['name'],now,before,sci)
                elif route=='/lucrare/new':
                    fid=sqlint(f.get('form_id'));r=c.execute('SELECT * FROM forms WHERE id=?',(fid,)).fetchone()
                    if not r or not form_access(c,u,fid) or not can_edit(u,r):return self.error('Fișa nu poate fi editată',403)
                    if not f.get('title','').strip():return self.error('Denumirea lucrării este obligatorie')
                    area=num(f.get('area_ha'))
                    if area is not None and area<0:return self.error('Suprafață invalidă')
                    before=form_snapshot(c,fid)
                    c.execute('INSERT INTO works(form_id,title,years,area_ha,notes) VALUES (?,?,?,?,?)',(fid,f['title'].strip(),f.get('years',''),area,f.get('notes','')));dest=f'/fisa/{fid}'
                    record_form_change(c,fid,'Lucrare adăugată',u['name'],now,before,f['title'].strip())
                
                elif route == '/fisa/delete':
                    if u['role'] != 'admin':
                        return self.error(
                            'Numai administratorul poate șterge fișe', 403
                        )

                    fid = sqlint(f.get('id'))

                    row = c.execute(
                        'SELECT unit_id FROM forms WHERE id=?',
                        (fid,)
                    ).fetchone()

                    if row is None:
                        return self.error('Fișa nu există', 404)

                    c.execute(
                        'DELETE FROM forms WHERE id=?',
                        (fid,)
                    )

                    dest = f'/ua/{row["unit_id"]}'
                elif route=='/fisa/reopen':
                    if u['role']!='admin':return self.error('Numai administratorul poate redeschide o fișă aprobată',403)
                    fid=sqlint(f.get('id'))
                    if not form_access(c,u,fid):return self.error('Acces interzis',403)
                    current=c.execute('SELECT * FROM forms WHERE id=?',(fid,)).fetchone()
                    if not current or current['status']!='Aprobată':return self.error('Poți redeschide doar o fișă aprobată',400)
                    before=form_snapshot(c,fid)
                    c.execute("""UPDATE forms SET status='Returnată', decision_by=NULL,
                        decision_at=NULL, approval_mode=NULL,
                        return_reason='Redeschisă de administrator pentru corectare', updated_at=?
                        WHERE id=?""",(now,fid))
                    record_form_change(c,fid,'Fișă aprobată redeschisă',u['name'],now,before,
                        'Versiunea aprobată anterioară este păstrată în istoric; este necesară retrimiterea.')
                    dest=f'/fisa/{fid}'
                elif route=='/fisa/status':
                    fid=sqlint(f.get('id'));status=f.get('status')
                    if not form_access(c,u,fid):return self.error('Acces interzis',403)
                    r=c.execute('SELECT * FROM forms WHERE id=?',(fid,)).fetchone()
                    if not r:return self.error('Fișa nu există',404)
                    if u['role'] in ('specialist','admin') and status in ('Aprobată','Transmisă') and can_edit(u,r):
                        # Accept also old, cached forms that still POST "Transmisă".
                        before=form_snapshot(c,fid)
                        c.execute("""UPDATE forms SET status='Aprobată', decision_by=?,decision_at=?,
                            approval_mode='Automată prin Trimite fișa',return_reason=NULL,
                            updated_at=? WHERE id=?""",(u['name'],now,now,fid))
                        record_form_change(c,fid,'Fișă aprobată automat',u['name'],now,before,
                            'Aprobare automată la apăsarea butonului Trimite fișa')
                        dest=f'/fisa/{fid}'
                    elif u['role']=='aprobator' and r['status'] in ('Transmisă','Verificată') and status in ('Aprobată','Returnată'):
                        # Keep the approver workflow for older forms that were sent before this release.
                        reason=f.get('reason','').strip()
                        if status=='Returnată' and not reason:return self.error('Completează motivul returnării')
                        before=form_snapshot(c,fid)
                        c.execute("""UPDATE forms SET status=?,decision_by=?,decision_at=?,
                            approval_mode=?,return_reason=?,updated_at=? WHERE id=?""",
                            (status,u['name'],now,'Manuală' if status=='Aprobată' else None,
                             reason if status=='Returnată' else '',now,fid))
                        record_form_change(c,fid,'Decizie aprobator: '+status,u['name'],now,before,reason)
                        dest=f'/fisa/{fid}'
                    else:return self.error('Tranziție nepermisă pentru rolul tău',403)
                else:return self.error('Acțiune necunoscută',404)
                c.execute('INSERT INTO audit(username,action,detail,happened_at) VALUES (?,?,?,?)',(u['name'],route,dest,now))
        except sqlite3.IntegrityError as e:return self.error('Înregistrare duplicată sau date nevalide: '+str(e))
        return self.redirect(dest)

if __name__=='__main__':
    init_db()
    print(f'GeoPajiști: http://127.0.0.1:{PORT}',flush=True)
    ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
