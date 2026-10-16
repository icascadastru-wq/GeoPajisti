"""Initialize database, import reference inventory once, then run the application."""
import os
from app import init_db,Handler,PORT,ThreadingHTTPServer
from import_putintei import execute
if __name__=='__main__':
    if not os.environ.get('ADMIN_PASSWORD') and not os.path.isfile(os.environ.get('DB_PATH','geopajisti.sqlite3')):
        raise SystemExit('Setați ADMIN_PASSWORD înainte de lansare.')
    execute()
    print(f'GeoPajiști pornit pe portul {PORT}',flush=True)
    ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
