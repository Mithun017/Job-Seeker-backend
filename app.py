import os
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
import pymysql
import firebase_admin  # Added missing import
from firebase_admin import credentials, auth
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
import requests
from pydantic import BaseModel
import time

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY') or 'fallback-secret-key-change-this')

# Validate environment variables
required_env_vars = ['SECRET_KEY', 'LINKEDIN_CLIENT_ID', 'LINKEDIN_CLIENT_SECRET', 'FIREBASE_API_KEY', 
                    'MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DATABASE']
for var in required_env_vars:
    if not os.getenv(var):
        raise ValueError(f"Missing {var} in .env file")

# Initialize Firebase Admin
try:
    if os.path.exists('firebase-service-account.json'):
        cred = credentials.Certificate('firebase-service-account.json')
        firebase_admin.initialize_app(cred)
    else:
        raise FileNotFoundError("firebase-service-account.json not found! Download from Firebase Console.")
except Exception as e:
    raise ValueError(f"Firebase initialization failed: {str(e)}")

# MySQL Database connection with retry
def get_db_connection(max_retries=3, delay=2):
    for attempt in range(max_retries):
        try:
            return pymysql.connect(
                host=os.getenv('MYSQL_HOST'),
                user=os.getenv('MYSQL_USER'),
                password=os.getenv('MYSQL_PASSWORD'),
                database=os.getenv('MYSQL_DATABASE'),
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
        except pymysql.MySQLError as e:
            if attempt < max_retries - 1:
                time.sleep(delay)
                continue
            raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

# Initialize users table if not exists
def init_db():
    with get_db_connection() as db:
        with db.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(255) PRIMARY KEY,
                    provider VARCHAR(50) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255),
                    picture VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            db.commit()

init_db()

# LinkedIn OAuth setup with OpenID Connect
oauth = OAuth()
oauth.register(
    name='linkedin',
    client_id=os.getenv('LINKEDIN_CLIENT_ID'),
    client_secret=os.getenv('LINKEDIN_CLIENT_SECRET'),
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    api_base_url='https://api.linkedin.com/',
    client_kwargs={'scope': 'openid profile email'},  # Updated to 'profile' and 'email' for OIDC
    server_metadata_url='https://www.linkedin.com/oauth/.well-known/openid-configuration'
)

# Pydantic model for Google token
class GoogleToken(BaseModel):
    idToken: str

@app.get("/")
async def index(request: Request):
    if 'user' in request.session:
        return {"success": True, "user": request.session['user']}
    raise HTTPException(status_code=401, detail="Not authenticated")

@app.get("/auth/linkedin")
async def auth_linkedin(request: Request):
    redirect_uri = "http://localhost:8000/auth/linkedin/callback"
    return await oauth.linkedin.authorize_redirect(request, redirect_uri)

@app.get("/auth/linkedin/callback")
async def auth_linkedin_callback(request: Request):
    try:
        token = await oauth.linkedin.authorize_access_token(request)
        if not token or 'access_token' not in token:
            raise HTTPException(status_code=400, detail="LinkedIn authorization failed")

        # Fetch user info using the OIDC userinfo endpoint
        userinfo_resp = requests.get(
            'https://api.linkedin.com/v2/userinfo',
            headers={'Authorization': f'Bearer {token["access_token"]}'}
        )
        if userinfo_resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch LinkedIn userinfo")

        userinfo = userinfo_resp.json()
        
        user_info = {
            'provider': 'linkedin',
            'id': userinfo.get('sub', ''),
            'name': userinfo.get('name', 'Unknown'),
            'email': userinfo.get('email', 'N/A'),
            'picture': userinfo.get('picture', '')
        }

        # Check if user exists
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM users WHERE id = %s AND provider = %s",
                    (user_info['id'], user_info['provider'])
                )
                user = cursor.fetchone()

        if user:
            request.session['user'] = user_info
            return JSONResponse({"success": True, "action": "login", "user": user_info})
        else:
            request.session['pending_user'] = user_info
            return JSONResponse({"success": True, "action": "register", "user": user_info})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LinkedIn auth error: {str(e)}")

@app.post("/auth/google/verify")
async def verify_google(token: GoogleToken, request: Request):
    id_token = token.idToken
    
    if not id_token:
        raise HTTPException(status_code=400, detail="No ID token provided")
    
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        user_info = auth.get_user(uid)
        
        user_data = {
            'provider': 'google',
            'id': uid,
            'name': user_info.display_name or 'Unknown',
            'email': user_info.email or 'N/A',
            'picture': user_info.photo_url or ''
        }
        
        # Check if user exists
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM users WHERE id = %s AND provider = %s",
                    (user_data['id'], user_data['provider'])
                )
                user = cursor.fetchone()

        if user:
            request.session['user'] = user_data
            return JSONResponse({"success": True, "action": "login", "user": user_data})
        else:
            request.session['pending_user'] = user_data
            return JSONResponse({"success": True, "action": "register", "user": user_data})

    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Google auth error: {str(e)}")

@app.post("/register")
async def register(request: Request):
    if 'pending_user' not in request.session:
        raise HTTPException(status_code=400, detail="No pending user data")
    
    user_info = request.session['pending_user']
    
    # Save user to database
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (id, provider, name, email, picture) VALUES (%s, %s, %s, %s, %s)",
                    (user_info['id'], user_info['provider'], user_info['name'], user_info['email'], user_info['picture'])
                )
                db.commit()
    except pymysql.MySQLError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    # Move pending user to session
    request.session['user'] = user_info
    del request.session['pending_user']
    return JSONResponse({"success": True, "action": "registered", "user": user_info})

@app.get("/dashboard")
async def dashboard(request: Request):
    if 'user' not in request.session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return JSONResponse({"success": True, "user": request.session['user']})

@app.get("/logout")
async def logout(request: Request):
    request.session.pop('user', None)
    request.session.pop('pending_user', None)
    return JSONResponse({"success": True, "message": "Logged out"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)