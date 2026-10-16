
"""Pornirea platformei GeoPajisti fara import automat."""
import os
from app import init_db, Handler, PORT, ThreadingHTTPServer

if __name__ == "__main__":
    if not os.environ.get("ADMIN_PASSWORD") and not os.path.isfile(
        os.environ.get("DB_PATH", "geopajisti.sqlite3")
    ):
        raise SystemExit("Setati ADMIN_PASSWORD in Railway.")

    init_db()

    print(f"GeoPajisti pornit pe portul {PORT}", flush=True)

    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
