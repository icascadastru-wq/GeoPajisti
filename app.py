"""GeoPajisti v0.1 - prototype for pasture field inventory, Python stdlib only."""
import csv, hashlib, hmac, html, io, json, os, secrets, sqlite3, threading
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
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'editor');
        CREATE TABLE IF NOT EXISTS municipalities(id INTEGER PRIMARY KEY, name TEXT NOT NULL, district TEXT NOT NULL DEFAULT '', UNIQUE(name,district));
        CREATE TABLE IF NOT EXISTS units(id INTEGER PRIMARY KEY, municipality_id INTEGER NOT NULL REFERENCES municipalities(id), code TEXT NOT NULL, name TEXT DEFAULT '', area REAL NOT NULL DEFAULT 0, UNIQUE(municipality_id,code));
        CREATE TABLE IF NOT EXISTS forms(id INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL REFERENCES units(id), inventory_date TEXT NOT NULL, author TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'Ciornă', locality TEXT DEFAULT '', altitude_min REAL, altitude_max REAL, slope REAL, aspect TEXT DEFAULT '', relief TEXT DEFAULT '', previous_management TEXT DEFAULT '', functional_group TEXT DEFAULT '', land_use TEXT DEFAULT '', watering_source TEXT DEFAULT '', landslide_ha REAL, erosion_ha REAL, moisture_ha REAL, stones_ha REAL, grass_cover_pct REAL, ruderal_pct REAL, woody_cover_pct REAL, pasture_type_code TEXT DEFAULT '', pasture_type_name TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS species(id INTEGER PRIMARY KEY, form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE, category TEXT NOT NULL, scientific_name TEXT NOT NULL, common_name TEXT DEFAULT '', participation_pct REAL);
        CREATE TABLE IF NOT EXISTS works(id INTEGER PRIMARY KEY, form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE, title TEXT NOT NULL, years TEXT DEFAULT '', area_ha REAL, notes TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT, happened_at TEXT NOT NULL);
        ''')
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

def field(name,label,value='',typ='text',step=None):
    stepattr=f' step="{step}"' if step else ''
    return f'<label>{esc(label)}<input type="{typ}" name="{esc(name)}" value="{esc(value)}"{stepattr}></label>'
def select(name, opts, current=''):
    return '<select name="%s">%s</select>' %(esc(name),''.join('<option value="%s" %s>%s</option>'%(esc(x),'selected' if x==current else '',esc(x)) for x in opts))
def layout(title, content, username=None):
    nav = ('<nav><a href="/">GeoPajiști</a> <a href="/primarii">Primării / UA</a> <a href="/rapoarte">Rapoarte</a> <a href="/logout">Ieșire</a></nav>' if username else '')
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
            if route in ('/','/primarii'):
                records=c.execute('SELECT m.*,COUNT(DISTINCT u.id) units, COUNT(DISTINCT f.id) forms FROM municipalities m LEFT JOIN units u ON u.municipality_id=m.id LEFT JOIN forms f ON f.unit_id=u.id GROUP BY m.id ORDER BY m.name').fetchall()
                lines=''.join(f'<tr><td><a href="/primarie/{r["id"]}">{esc(r["name"])}</a></td><td>{esc(r["district"])}</td><td>{r["units"]}</td><td>{r["forms"]}</td></tr>' for r in records)
                form=f'<form method="post" action="/primarii" class="card"><h2>Adaugă primărie</h2>{self.hidden()}<div class="grid">{field("name","Denumire primărie")}{field("district","Raion")}</div><button>Adaugă</button></form>'
                content=f'<h1>Primării</h1><p class="muted">Primărie → UA → Fișe de teren</p><table><tr><th>Primărie</th><th>Raion</th><th>UA</th><th>Fișe</th></tr>{lines}</table>'+form
                return self.send_page(layout('Primării',content,u))
            if route.startswith('/primarie/'):
                mid=sqlint(route.rsplit('/',1)[1]);m=c.execute('SELECT * FROM municipalities WHERE id=?',(mid,)).fetchone()
                if not m:return self.error('Primăria nu există',404)
                rows=c.execute('SELECT u.*, (SELECT COUNT(*) FROM forms f WHERE f.unit_id=u.id) forms FROM units u WHERE municipality_id=? ORDER BY code',(mid,)).fetchall()
                
                table = ''
                for r in rows:
                    delete_button = ''

                    if u['role'] == 'admin' and r['forms'] == 0:
                        delete_button = (
                            '<form method="post" action="/ua/delete" '
                            'onsubmit="return confirm(\'Sigur ștergi această UA?\')" '
                            'style="display:inline-block;margin-left:10px">'
                            + self.hidden()
                            + f'<input type="hidden" name="id" value="{r["id"]}">'
                            + '<button type="submit" style="background:#b42318">'
                            'Șterge UA</button></form>'
                        )

                    table += (
                        f'<tr><td><a href="/ua/{r["id"]}">{esc(r["code"])}</a></td>'
                        f'<td>{esc(r["name"])}</td>'
                        f'<td>{esc(r["area"])}</td>'
                        f'<td>{r["forms"]}{delete_button}</td></tr>'
                    )
                form=f'<form method="post" action="/ua/new" class="card"><h2>UA nouă</h2>{self.hidden()}<input type="hidden" name="municipality_id" value="{mid}"><div class="grid">{field("code","Cod UA")}{field("name","Denumirea sectorului")}{field("area","Suprafața (ha)","","number","any")}</div><button>Adaugă UA</button></form>'
                return self.send_page(layout('Primărie',f'<a href="/primarii">← Primării</a><h1>{esc(m["name"])}</h1><table><tr><th>UA</th><th>Denumire</th><th>Suprafață (ha)</th><th>Fișe</th></tr>{table}</table>'+form,u))
            if route.startswith('/ua/'):
                uid=sqlint(route.rsplit('/',1)[1]);unit=c.execute('SELECT u.*,m.name municipality FROM units u JOIN municipalities m ON u.municipality_id=m.id WHERE u.id=?',(uid,)).fetchone()
                if not unit:return self.error('UA nu există',404)
                rows=c.execute('SELECT * FROM forms WHERE unit_id=? ORDER BY inventory_date DESC,id DESC',(uid,)).fetchall()
                lines=''.join(f'<tr><td><a href="/fisa/{r["id"]}">Fișa #{r["id"]}</a></td><td>{esc(r["inventory_date"])}</td><td>{esc(r["author"])}</td><td>{esc(r["status"])}</td></tr>' for r in rows)
                form=f'<form method="post" action="/fisa/new" class="card"><h2>Înregistrare fișă nouă</h2>{self.hidden()}<input type="hidden" name="unit_id" value="{uid}"><div class="grid">{field("inventory_date","Data inventarierii",datetime.now().strftime("%Y-%m-%d"),"date")}{field("author","Specialist")}</div><button>Creare fișă</button></form>'
                return self.send_page(layout('Unitate amenajistică',f'<a href="/primarie/{unit["municipality_id"]}">← Primărie</a><h1>{esc(unit["municipality"])} / UA {esc(unit["code"])}</h1><p>Suprafața UA: {esc(unit["area"])} ha</p><table><tr><th>Fișa</th><th>Data</th><th>Specialist</th><th>Stare</th></tr>{lines}</table>'+form,u))
            if route.startswith('/fisa/'):
                fid=sqlint(route.rsplit('/',1)[1]);r=c.execute('SELECT f.*,u.code,u.area,u.municipality_id,m.name municipality FROM forms f JOIN units u ON f.unit_id=u.id JOIN municipalities m ON u.municipality_id=m.id WHERE f.id=?',(fid,)).fetchone()
                if not r:return self.error('Fișa nu există',404)
                species=c.execute('SELECT * FROM species WHERE form_id=? ORDER BY category,id',(fid,)).fetchall()
                works=c.execute('SELECT * FROM works WHERE form_id=? ORDER BY id',(fid,)).fetchall()
                if p.query=='print':return self.send_page(self.print_form(r,species,works))
                return self.send_page(layout(f'Fișa #{fid}',self.edit_form(r,species,works),u))
            if route=='/rapoarte':
                rows=c.execute('SELECT m.id,m.name,m.district,COUNT(DISTINCT u.id) unit_count,COUNT(DISTINCT f.id) form_count,COALESCE(SUM(DISTINCT u.area),0) approx_area FROM municipalities m LEFT JOIN units u ON u.municipality_id=m.id LEFT JOIN forms f ON f.unit_id=u.id GROUP BY m.id ORDER BY m.name').fetchall()
                lines=''.join(f'<tr><td>{esc(x["name"])}</td><td>{x["unit_count"]}</td><td>{x["form_count"]}</td><td><a href="/export?primarie={x["id"]}">CSV</a></td></tr>' for x in rows)
                return self.send_page(layout('Rapoarte',f'<h1>Rapoarte și exporturi</h1><p>Exportul CSV conține câte o linie pentru fiecare fișă, fără a dubla suprafețele UA. Detaliile speciilor și lucrărilor se descarcă separat.</p><div class="actions"><a class="btn" href="/export">Toate fișele CSV</a><a class="btn secondary" href="/export-specii">Toate speciile CSV</a><a class="btn secondary" href="/export-lucrari">Toate lucrările CSV</a></div><table><tr><th>Primărie</th><th>UA</th><th>Fișe</th><th>Export</th></tr>{lines}</table><p>Fișele individuale pot fi imprimate sau salvate ca PDF din browser.</p>',u))
            if route.startswith('/export'):
                data=parse_qs(p.query);municipality=sqlint(data.get('primarie',['0'])[0]);
                where=' WHERE m.id=?' if municipality else '';args=(municipality,) if municipality else ()
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
        editable=r['status']!='Aprobată'; fid=r['id']
        def f(name,label,typ='text'):return field(name,label,r[name],typ,'any' if typ=='number' else None)
        parts=f'<a href="/ua/{r["unit_id"]}">← UA {esc(r["code"])}</a><h1>Fișă #{fid} · {esc(r["municipality"])} / UA {esc(r["code"])}</h1><p>Stare: <strong>{esc(r["status"])}</strong> · Suprafața UA: {esc(r["area"])} ha</p><div class="actions"><a class="btn secondary" href="/fisa/{fid}?print" target="_blank">Fișă pentru imprimare / PDF</a></div>'
        parts+=f'<form method="post" action="/fisa/save" class="card">{self.hidden()}<input type="hidden" name="id" value="{fid}"><h2>Date generale</h2><div class="grid">{f("inventory_date","Data inventarierii","date")}{f("author","Specialist")}{f("locality","Trup / localitate")}{f("previous_management","Gospodărirea anterioară")}{f("functional_group","Grupa funcțională")}{f("land_use","Categoria de folosință")}{f("watering_source","Sursa de adăpare")}</div><h2>Descrierea stațiunii</h2><div class="grid">{f("altitude_min","Altitudine minimă m","number")}{f("altitude_max","Altitudine maximă m","number")}{f("relief","Relief")}{f("slope","Înclinare grade","number")}{f("aspect","Expoziție")}{f("landslide_ha","Alunecări ha","number")}{f("erosion_ha","Eroziune ha","number")}{f("moisture_ha","Exces umiditate ha","number")}{f("stones_ha","Petriș ha","number")}{f("grass_cover_pct","Acoperire covor ierbos %","number")}{f("ruderal_pct","Vegetație ruderală %","number")}{f("woody_cover_pct","Vegetație lemnoasă %","number")}</div><h2>Tipul pajiștii</h2><div class="grid">{f("pasture_type_code","Cod tip")}{f("pasture_type_name","Denumire tip")}</div><label>Observații<textarea name="notes" rows="4">{esc(r["notes"])}</textarea></label>'
        parts+=self.historical_details(fid)
        if editable:parts+='<button>Salvează fișa</button>'
        parts+='</form>'
        parts+='<div class="card"><h2>Specii înregistrate</h2><table><tr><th>Grup</th><th>Specie</th><th>Populară</th><th>%</th></tr>'+''.join(f'<tr><td>{esc(x["category"])}</td><td>{esc(x["scientific_name"])}</td><td>{esc(x["common_name"])}</td><td>{esc(x["participation_pct"])}</td></tr>' for x in species)+'</table></div>'
        if editable:
            parts+=f'<form method="post" action="/specie/new" class="card">{self.hidden()}<input type="hidden" name="form_id" value="{fid}"><h3>Adaugă specie</h3><div class="grid"><label>Grup{select("category",["Graminee","Fabacee","Alte familii botanice","Vegetație lemnoasă"])}</label>{field("scientific_name","Denumire științifică")}{field("common_name","Denumire populară")}{field("participation_pct","Participare %","number","any")}</div><button>Adaugă specie</button></form>'
        parts+='<div class="card"><h2>Lucrări propuse</h2><table><tr><th>Lucrare</th><th>Ani</th><th>ha</th><th>Observații</th></tr>'+''.join(f'<tr><td>{esc(x["title"])}</td><td>{esc(x["years"])}</td><td>{esc(x["area_ha"])}</td><td>{esc(x["notes"])}</td></tr>' for x in works)+'</table></div>'
        if editable:
            parts+=f'<form method="post" action="/lucrare/new" class="card">{self.hidden()}<input type="hidden" name="form_id" value="{fid}"><h3>Adaugă lucrare</h3><div class="grid">{field("title","Denumire lucrare")}{field("years","Ani execuție")}{field("area_ha","Suprafață ha","number","any")}{field("notes","Observații")}</div><button>Adaugă lucrare</button></form>'
            parts+=f'<form method="post" action="/fisa/status" class="card">{self.hidden()}<input type="hidden" name="id" value="{fid}"><h3>Transmitere și aprobare</h3><label>Stare{select("status",["Ciornă","Transmisă","Verificată","Aprobată"],r["status"])}</label><button>Actualizează starea</button></form>'
       
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
    def print_form(self,r,species,works):
        def v(x):return esc(r[x])
        content=f'<h1>FIȘĂ DE INVENTARIERE A PAJIȘTII – #{r["id"]}</h1><p><b>Primăria:</b> {v("municipality")} &nbsp; <b>UA:</b> {v("code")} &nbsp; <b>Suprafața:</b> {v("area")} ha</p><p><b>Data:</b> {v("inventory_date")} &nbsp; <b>Specialist:</b> {v("author")}</p><h2>Caracteristici</h2><table>'
        labels={'locality':'Trup','previous_management':'Gospodărire anterioară','functional_group':'Grupa funcțională','land_use':'Categoria de folosință','watering_source':'Sursa de adăpare','altitude_min':'Altitudine min. m','altitude_max':'Altitudine max. m','relief':'Relief','slope':'Pantă grade','aspect':'Expoziție','landslide_ha':'Alunecări ha','erosion_ha':'Eroziune ha','moisture_ha':'Exces umiditate ha','stones_ha':'Petriș ha','grass_cover_pct':'Covor ierbos %','ruderal_pct':'Ruderală %','woody_cover_pct':'Vegetație lemnoasă %','pasture_type_code':'Cod pajiște','pasture_type_name':'Tip pajiște','notes':'Observații'}
        content+=''.join(f'<tr><th>{esc(label)}</th><td>{v(key)}</td></tr>' for key,label in labels.items())+'</table>'+self.historical_details(r['id'])+'<h2>Specii</h2><table><tr><th>Grup</th><th>Specie</th><th>Denumire populară</th><th>Participare %</th></tr>'+''.join(f'<tr><td>{esc(s["category"])}</td><td>{esc(s["scientific_name"])}</td><td>{esc(s["common_name"])}</td><td>{esc(s["participation_pct"])}</td></tr>' for s in species)+'</table><h2>Lucrări propuse</h2><table><tr><th>Lucrare</th><th>Ani</th><th>Suprafață ha</th></tr>'+''.join(f'<tr><td>{esc(w["title"])}</td><td>{esc(w["years"])}</td><td>{esc(w["area_ha"])}</td></tr>' for w in works)+'</table><div class="actions"><button onclick="window.print()">Imprimă / salvează PDF</button></div>'
        return layout('Fișă imprimabilă',content)
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
                if route=='/primarii':
                    if not f.get('name','').strip():return self.error('Denumirea primăriei este obligatorie')
                    cursor=c.execute('INSERT INTO municipalities(name,district) VALUES (?,?)',(f['name'].strip(),f.get('district','').strip()));dest=f'/primarie/{cursor.lastrowid}'
                elif route=='/ua/new':
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
                    uid=sqlint(f.get('unit_id'))
                    cursor=c.execute('INSERT INTO forms(unit_id,inventory_date,author,created_at,updated_at) VALUES (?,?,?,?,?)',(uid,f.get('inventory_date',''),f.get('author',''),now,now));dest=f'/fisa/{cursor.lastrowid}'
                elif route=='/fisa/save':
                    fid=sqlint(f.get('id'))
                    if c.execute('SELECT status FROM forms WHERE id=?',(fid,)).fetchone()['status']=='Aprobată':return self.error('Fișa aprobată este blocată')
                    textfields=['inventory_date','author','locality','previous_management','functional_group','land_use','watering_source','relief','aspect','pasture_type_code','pasture_type_name','notes']
                    numeric=['altitude_min','altitude_max','slope','landslide_ha','erosion_ha','moisture_ha','stones_ha','grass_cover_pct','ruderal_pct','woody_cover_pct']
                    fields=textfields+numeric+['updated_at'];values=[f.get(x,'').strip() for x in textfields]+[num(f.get(x,'')) for x in numeric]+[now]
                    for col in ['grass_cover_pct','ruderal_pct','woody_cover_pct']:
                        n=num(f.get(col));
                        if n is not None and not 0<=n<=100:return self.error('Procentele trebuie să fie între 0 și 100')
                    c.execute('UPDATE forms SET '+','.join(x+'=?' for x in fields)+' WHERE id=?',values+[fid]);dest=f'/fisa/{fid}'
                elif route=='/specie/new':
                    fid=sqlint(f.get('form_id'));r=c.execute('SELECT status FROM forms WHERE id=?',(fid,)).fetchone()
                    if not r or r['status']=='Aprobată':return self.error('Fișa nu poate fi editată')
                    if not f.get('scientific_name','').strip():return self.error('Specia este obligatorie')
                    pct=num(f.get('participation_pct'))
                    if pct is not None and not 0<=pct<=100:return self.error('Procent invalid')
                    c.execute('INSERT INTO species(form_id,category,scientific_name,common_name,participation_pct) VALUES (?,?,?,?,?)',(fid,f.get('category',''),f['scientific_name'].strip(),f.get('common_name',''),pct));dest=f'/fisa/{fid}'
                elif route=='/lucrare/new':
                    fid=sqlint(f.get('form_id'));r=c.execute('SELECT status FROM forms WHERE id=?',(fid,)).fetchone()
                    if not r or r['status']=='Aprobată':return self.error('Fișa nu poate fi editată')
                    if not f.get('title','').strip():return self.error('Denumirea lucrării este obligatorie')
                    area=num(f.get('area_ha'))
                    if area is not None and area<0:return self.error('Suprafață invalidă')
                    c.execute('INSERT INTO works(form_id,title,years,area_ha,notes) VALUES (?,?,?,?,?)',(fid,f['title'].strip(),f.get('years',''),area,f.get('notes','')));dest=f'/fisa/{fid}'
                
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
                elif route=='/fisa/status':
                    fid=sqlint(f.get('id'));status=f.get('status')
                    if status not in ('Ciornă','Transmisă','Verificată','Aprobată'):return self.error('Stare invalidă')
                    if status in ('Verificată','Aprobată') and u['role']!='admin':return self.error('Numai administratorul poate verifica sau aproba',403)
                    current=c.execute('SELECT status FROM forms WHERE id=?',(fid,)).fetchone()
                    if not current or current['status']=='Aprobată':return self.error('Fișa nu mai poate fi modificată')
                    c.execute('UPDATE forms SET status=?,updated_at=? WHERE id=?',(status,now,fid));dest=f'/fisa/{fid}'
                else:return self.error('Acțiune necunoscută',404)
                c.execute('INSERT INTO audit(username,action,detail,happened_at) VALUES (?,?,?,?)',(u['name'],route,dest,now))
        except sqlite3.IntegrityError as e:return self.error('Înregistrare duplicată sau date nevalide: '+str(e))
        return self.redirect(dest)

if __name__=='__main__':
    init_db()
    print(f'GeoPajiști: http://127.0.0.1:{PORT}',flush=True)
    ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
