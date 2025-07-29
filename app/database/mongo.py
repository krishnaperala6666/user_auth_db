from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING

client = AsyncIOMotorClient("mongodb+srv://dinunaik65:hjKj4di7aPjdirPX@user-data.yvlc9zz.mongodb.net/")
database = client["user_registration_model"]
users_collection = database["users"]
blacklist_collection = database["blacklisted_tokens"]

