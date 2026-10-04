import sqlite3

connection = sqlite3.connect("netguardian.db")

cursor = connection.cursor()

cursor.execute(
    "DELETE FROM devices WHERE ip_address = ?",
    ("192.168.8.250",)
)

connection.commit()
connection.close()

print("Test device removed successfully.")