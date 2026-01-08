from config import Settings
from db import ensure_dir, init_db

if __name__ == "__main__":
    s = Settings()
    ensure_dir(s.data_dir)
    init_db(s.db_path)
    print(f"Initialized DB at {s.db_path}")

