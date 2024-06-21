import os
import psycopg2
from psycopg2 import OperationalError

db_url = os.getenv('DATABASE_URL')

if not db_url:
    print("DATABASE_URL environment variable is not set.")
else:
    try:
        conn = psycopg2.connect(db_url)
        print("Database connected successfully")
        conn.close()
    except OperationalError as e:
        print(f"Error: {e}")
