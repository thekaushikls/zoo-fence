#!/usr/bin/bin/python3.12

# - - - - IMPORTS
from os import getenv
from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter
from typing import Optional
from pymongo import MongoClient
from . import utils, models

# - - - - GLOBALS
load_dotenv()
cluster = MongoClient(getenv("DATABASE_URL"))
db = cluster[getenv("DATABASE_NAME")]
app = FastAPI()
routes = APIRouter()

# - - - - HELPERS
def is_valid_username(username: str) -> bool:
    if username is None: return False
    return len(username) > 0

def is_valid_email(email: str) -> bool:
    if email is None: return False
    return len(email) > 0

def is_valid_password(password: str) -> bool:
    return len(password) >= 8

# - - - - METHODS
def get_user_count() -> int:
    return db.get_collection("users").count_documents({})

def get_user(email: Optional[str] = None, username: Optional[str] = None) -> dict:

    if is_valid_email(email) or is_valid_username(username): 
        query = {
            "$or": [ 
                { "email": email },
                { "username": username } 
            ]
        }

        user = db.get_collection("users").find_one(query)
        if user:

            return {
                "status": 200,
                "message": "User found",
                "user": utils.map_mongo_id(user)
            }
        else:
            return {
                "status": 404,
                "message": "User not found.",
                "user": None
            }
    else:
        return {
            "status": 400,
            "message": "Email and/or Username invalid.",
            "user": None
        }

# - - - - API ROUTES
@routes.get("/")
async def root():
    
    status = {
        "webapp": None,
        "database": None
    }

    # Web Application Status
    status["webapp"] = {
        "status": 200,
        "message": "✅ Running Successfully"
    }

    # Database Connection Status
    try:
        count = get_user_count()
        status["database"] = {
            "status": 200,
            "message": "✅ Connection Successful"
        }
    except Exception as ex:
        status["database"] = {
            "status": 500,
            "message": "❌ Connection Failed"
        }
        status["error"] = str(ex)
    
    return status

@routes.post("/api/signUp")
async def sign_up(user: models.User):
    # Check if user already exists
    result = get_user(user.email, user.username)

    if result["status"] == 200:
        return {
            "status": 409,
            "message": "Email or username already exists."
        }
    
    elif result["status"] == 404:
        new_user = user.model_dump()
        
        _password, _salt = utils.hash_password(user.password)
        new_user.update({"password": _password, "salt": _salt})
        
        result = db.get_collection("users").insert_one(new_user)        
        return {
            "status": 200,
            "message": "User created successfully!",
            "id": str(result.inserted_id)
        }
    
    else:
        return {
            "status": result["status"],
            "message": result["message"]
        }

@routes.get("/api/signIn")
async def sign_in(password: str, email: Optional[str] = None, username: Optional[str] = None):
    if password is None or len(password) < utils.MIN_PASSWORD_LENGTH:
        return {
            "status": 403,
            "message": "Password needs to be at least 8 characters long."
        }
    
    # Check if user already exists
    result = get_user(email, username)
    user = result["user"]
    if result["status"] == 200 and user:
        
        hashed_input_password, _ = utils.hash_password(password, user["salt"])

        if hashed_input_password == user["password"]:
            return {
                "status": 200,
                "success": True,
                "message": "Authorization successful."
            }
        else:
            return{
                "status": 403,
                "success": False,
                "message": "Authorization failed!"
            }
    
    else:
        return {
            "status": 404,
            "message": "Email or username not found!",
        }
        
# - - - - FOOTER
app.include_router(router=routes)
