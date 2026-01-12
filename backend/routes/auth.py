"""
Authentication routes
Handles user registration, login, and profile
"""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import bcrypt
import jwt
import os
import traceback
from dotenv import load_dotenv
from bson import ObjectId
from pydantic import BaseModel, EmailStr, Field

from database import get_users_collection

load_dotenv()

router = APIRouter()
security = HTTPBearer()

# JWT settings
SECRET_KEY = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# ==================== SCHEMAS ====================

class UserRegister(BaseModel):
    """Schema for user registration request"""
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    """Schema for user login request"""
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    """Schema for user response (excludes password)"""
    id: str
    name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    """Schema for JWT token response"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# ==================== HELPERS ====================

def hash_password(password: str) -> str:
    """Hash a password using bcrypt directly - no passlib"""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash using bcrypt directly"""
    try:
        password_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False

def create_access_token(user_id: str, email: str) -> str:
    """Create a JWT access token"""
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": user_id,
        "email": email,
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Dependency to get the current authenticated user.
    Verifies JWT token and returns user data.
    """
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user from database
        users = get_users_collection()
        user = await users.find_one({"_id": ObjectId(user_id)})
        
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return {
            "id": str(user["_id"]),
            "email": user["email"],
            "name": user["name"],
            "created_at": user["created_at"]
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

# ==================== ROUTES ====================

@router.post("/register", response_model=TokenResponse)
async def register(user_data: UserRegister):
    """
    Register a new user.
    Returns JWT token on success.
    """
    try:
        users = get_users_collection()
        
        if users is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not connected"
            )
        
        # Check if email already exists
        existing_user = await users.find_one({"email": user_data.email.lower()})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered. Please use a different email or login."
            )
        
        # Create new user document
        new_user = {
            "name": user_data.name.strip(),
            "email": user_data.email.lower().strip(),
            "hashed_password": hash_password(user_data.password),
            "created_at": datetime.utcnow()
        }
        
        # Insert into MongoDB - PERMANENT STORAGE
        result = await users.insert_one(new_user)
        user_id = str(result.inserted_id)
        
        print(f"✅ User registered and saved to MongoDB: {user_data.email}")
        
        # Create JWT token
        token = create_access_token(user_id, user_data.email.lower())
        
        return TokenResponse(
            access_token=token,
            user=UserResponse(
                id=user_id,
                name=new_user["name"],
                email=new_user["email"],
                created_at=new_user["created_at"]
            )
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        print(f"❌ Registration error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/login", response_model=TokenResponse)
async def login(user_data: UserLogin):
    """
    Login an existing user.
    Returns JWT token on success.
    """
    try:
        users = get_users_collection()
        
        if users is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not connected"
            )
        
        # Find user by email in MongoDB (case-insensitive)
        user = await users.find_one({"email": user_data.email.lower()})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Verify password
        if not verify_password(user_data.password, user["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        user_id = str(user["_id"])
        
        print(f"✅ User logged in from MongoDB: {user_data.email}")
        
        # Create JWT token
        token = create_access_token(user_id, user["email"])
        
        return TokenResponse(
            access_token=token,
            user=UserResponse(
                id=user_id,
                name=user["name"],
                email=user["email"],
                created_at=user["created_at"]
            )
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """
    Get the current authenticated user's profile.
    Requires valid JWT token in Authorization header.
    """
    return UserResponse(**current_user)

@router.get("/users")
async def get_all_users():
    """
    Get all users (for testing purposes).
    """
    try:
        users = get_users_collection()
        
        if users is None:
            return {"users": [], "count": 0, "error": "Database not connected"}
        
        # Find all users in MongoDB
        cursor = users.find({})
        user_list = []
        
        async for user in cursor:
            user_list.append({
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "created_at": user["created_at"]
            })
        
        return {"users": user_list, "count": len(user_list)}
        
    except Exception as e:
        print(f"❌ Error fetching users: {str(e)}")
        return {"users": [], "count": 0, "error": str(e)}
