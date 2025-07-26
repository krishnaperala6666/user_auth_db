from pymongo import MongoClient
import mysql.connector
from app.config import MONGO_URL, MONGO_DB_NAME, USER_COLLECTION

# MongoDB Connection
client = MongoClient(MONGO_URL)
db = client[MONGO_DB_NAME]
user_collection = db[USER_COLLECTION]

# MySQL Connection
mysql_conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="yourpassword",
    database="user_auth_db"
)
mysql_cursor = mysql_conn.cursor()
mysql_cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    dob DATE,
    doj DATE,
    address TEXT,
    comment TEXT,
    active BOOLEAN,
    password TEXT,
    last_password_change DATETIME,
    password_history TEXT
)
""")
mysql_conn.commit()