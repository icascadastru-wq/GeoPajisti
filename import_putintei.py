"""Import one historical inventory per Excel sheet, preserving original records.
Run after init_db; does not overwrite existing imported data.
"""
import csv,json,os,re,sqlite3
from datetime import datetime
from pathlib import Path
from app import init_db,conn,num
BASE=Path(__file__).parent/'import_data'
def load(name):
    with (BASE/name).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def maybe(v):return num(v) if v not in ('',None) else None
def execute():
    init_db()
    rows=load('unitati_amenajistice.csv'); sp=load('observatii_specii.csv'); soils=load('tipuri_sol.csv'); works=load('lucrari_propuse.csv')
    with conn() as db:
        db.execute('CREATE TABLE IF NOT EXISTS legacy_data(form_id INTEGER PRIMARY KEY REFERENCES forms(id), source_key TEXT UNIQUE, source_sheet TEXT, original_ua TEXT, payload_json TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS soils(id INTEGER PRIMARY KEY,form_id INTEGER REFERENCES forms(id),soil_code TEXT,area_ha REAL,percent REAL)')
        db.execute('CREATE TABLE IF NOT EXISTS legacy_species_notes(species_id INTEGER PRIMARY KEY REFERENCES species(id), original_text TEXT, dispersal TEXT, density TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS legacy_work_targets(work_id INTEGER PRIMARY KEY REFERENCES works(id), gram_pct REAL,fab_pct REAL,other_pct REAL,woody_element TEXT,prp TEXT)')
        db.execute('INSERT OR IGNORE INTO municipalities(name,district) VALUES (?,?)',('Putinței',''))
        mid=db.execute('SELECT id FROM municipalities WHERE name=? AND district=?',('Putinței','')).fetchone()['id']
        ids={}; used=set(r['code'] for r in db.execute('SELECT code FROM units WHERE municipality_id=?',(mid,)))
        for r in rows:
            old=db.execute('SELECT form_id FROM legacy_data WHERE source_key=?',(r['id_import'],)).fetchone()
            if old:ids[r['id_import']]=old['form_id'];continue
            code=r['ua'].strip(); original=code
            if code in used:
                ix=2
                while f'{code}~{ix}' in used:ix+=1
                code=f'{code}~{ix}'
            used.add(code)
            cur=db.execute('INSERT INTO units(municipality_id,code,name,area) VALUES (?,?,?,?)',(mid,code,r['denumire_trup'],maybe(r['suprafata_ha']) or 0))
            uid=cur.lastrowid
            a=r['altitudine'].replace('–','-').replace('—','-').strip()
            parts=re.findall(r'\d+(?:[.,]\d+)?',a)
            amin=maybe(parts[0]) if parts else None; amax=maybe(parts[1]) if len(parts)>1 else amin
            stamp='2015-03-23T00:00:00Z'
            cur=db.execute('''INSERT INTO forms(unit_id,inventory_date,author,status,locality,altitude_min,altitude_max,slope,aspect,previous_management,functional_group,land_use,watering_source,landslide_ha,erosion_ha,moisture_ha,stones_ha,grass_cover_pct,ruderal_pct,woody_cover_pct,pasture_type_code,pasture_type_name,notes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(
            uid,'2015-03-23','Import istoric Excel','Aprobată',r['denumire_trup'],amin,amax,maybe(r['inclinare_grade']),r['expozitie'],r['gospodarire_anterioara'],r['grupa_functionala'],r['categorie_folosinta'],r['sursa_adapare'],maybe(r['alunecari_ha']),maybe(r['eroziune_ha']),maybe(r['exces_umiditate_ha']),maybe(r['pietris_ha']),maybe(r['acoperire_ierbos_pct']),maybe(r['vegetatie_ruderala_pct']),maybe(r['vegetatie_lemnoasa_pct']),r['tip_pajiste_cod'],r['tip_pajiste_denumire'],'Fișă istorică importată; data provine din numele registrului Excel și trebuie verificată.',stamp,stamp))
            fid=cur.lastrowid;ids[r['id_import']]=fid
            db.execute('INSERT INTO legacy_data(form_id,source_key,source_sheet,original_ua,payload_json) VALUES (?,?,?,?,?)',(fid,r['id_import'],r['foaie_sursa'],original,json.dumps(r,ensure_ascii=False)))
        existing_species={x['form_id'] for x in db.execute('SELECT DISTINCT s.form_id FROM species s JOIN legacy_species_notes l ON l.species_id=s.id')}
        for r in sp:
            fid=ids.get(r['id_import'])
            if not fid or fid in existing_species:continue
            categories={'graminee':'Graminee','fabacee':'Fabacee','alte_familii':'Alte familii botanice','vegetatie_lemnoasa':'Vegetație lemnoasă'}
            raw=r['specie_text_original']; name=raw.split('(')[0].strip(); common=raw.split('(',1)[-1].rstrip(')').strip() if '(' in raw else ''
            cur=db.execute('INSERT INTO species(form_id,category,scientific_name,common_name,participation_pct) VALUES (?,?,?,?,?)',(fid,categories.get(r['grupa'],r['grupa']),name,common,maybe(r['participare_pct'])))
            db.execute('INSERT INTO legacy_species_notes(species_id,original_text,dispersal,density) VALUES (?,?,?,?)',(cur.lastrowid,raw,r['raspandire'],r['densitate']))
        for r in soils:
            fid=ids.get(r['id_import'])
            if fid and not db.execute('SELECT 1 FROM soils WHERE form_id=? AND soil_code=? AND area_ha IS ?',(fid,r['cod_sol'],maybe(r['suprafata_ha']))).fetchone():
                db.execute('INSERT INTO soils(form_id,soil_code,area_ha,percent) VALUES (?,?,?,?)',(fid,r['cod_sol'],maybe(r['suprafata_ha']),maybe(r['pondere_pct'])))
        for r in works:
            fid=ids.get(r['id_import'])
            if not fid:continue
            if db.execute('SELECT 1 FROM works w JOIN legacy_work_targets l ON w.id=l.work_id WHERE w.form_id=? AND w.title=? AND w.years=?',(fid,r['lucrare'],r['an_executare'])).fetchone():continue
            cur=db.execute('INSERT INTO works(form_id,title,years,area_ha,notes) VALUES (?,?,?,?,?)',(fid,r['lucrare'],r['an_executare'],maybe(r['suprafata_ha']),'Import istoric'))
            db.execute('INSERT INTO legacy_work_targets(work_id,gram_pct,fab_pct,other_pct,woody_element,prp) VALUES (?,?,?,?,?,?)',(cur.lastrowid,maybe(r['tinta_graminee_pct']),maybe(r['tinta_fabacee_pct']),maybe(r['tinta_alte_familii_pct']),r['element_arb'],r['prp']))
        summary={t:db.execute('SELECT count(*) n FROM '+t).fetchone()['n'] for t in ('municipalities','units','forms','species','works','soils')}
        print(summary)
if __name__=='__main__':execute()
