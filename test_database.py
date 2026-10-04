import sqlite3

connection = sqlite3.connect("netguardian.db")

cursor = connection.cursor()

cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type='table'
""")

tables = cursor.fetchall()

print("Database tables:")

for table in tables:
    print("-", table[0])

connection.close()