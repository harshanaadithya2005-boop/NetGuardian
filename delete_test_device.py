from database.db import get_connection

connection = get_connection()
cursor = connection.cursor()

cursor.execute(
    "DELETE FROM devices WHERE ip_address = ?",
    ("192.168.8.250",)
)

connection.commit()
connection.close()

print("Test device removed successfully.")