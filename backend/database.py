"""
Database connection module
Handles MongoDB connection using Motor (async driver)
"""

import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB connection settings
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attendance_tracker")

# Global database client
client: AsyncIOMotorClient = None
database = None

async def connect_to_mongo():
    """
    Connect to MongoDB on startup.
    The connection persists throughout the application lifecycle.
    """
    global client, database
    
    print(f"Connecting to MongoDB at {MONGODB_URI}...")
    
    client = AsyncIOMotorClient(MONGODB_URI)
    database = client[DATABASE_NAME]
    
    # Test the connection
    try:
        await client.admin.command('ping')
        print(f"✅ Connected to MongoDB database: {DATABASE_NAME}")
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        raise e

async def close_mongo_connection():
    """
    Close MongoDB connection on shutdown.
    """
    global client
    
    if client:
        client.close()
        print("MongoDB connection closed")

def get_database():
    """
    Get the database instance.
    Use this in route handlers.
    """
    return database

# Collection getters for easy access
def get_users_collection():
    return database["users"]

def get_subjects_collection():
    return database["subjects"]

def get_attendance_collection():
    return database["attendance"]
