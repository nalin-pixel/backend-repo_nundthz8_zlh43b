import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User as UserSchema, Preference as PreferenceSchema, WaveContent as WaveContentSchema

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------- Utility functions ----------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    email: Optional[EmailStr] = None


class PublicUser(BaseModel):
    name: str
    email: EmailStr
    preferences: Optional[PreferenceSchema] = None


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_email(email: str) -> Optional[dict]:
    if db is None:
        return None
    doc = db["user"].find_one({"email": email})
    return doc


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = get_user_by_email(token_data.email)
    if user is None:
        raise credentials_exception
    return user


# ---------------------- Routes ----------------------
@app.get("/")
def read_root():
    return {"message": "EM Waves API running"}


# Auth
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


@app.post("/auth/signup")
def signup(payload: SignupRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = hash_password(payload.password)
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": password_hash,
        "salt": "",
        "preferences": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["user"].insert_one(user_doc)
    return {"message": "Signup successful"}


@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if user is None or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me", response_model=PublicUser)
def me(current_user: dict = Depends(get_current_user)):
    return {
        "name": current_user.get("name"),
        "email": current_user.get("email"),
        "preferences": current_user.get("preferences"),
    }


# Preferences
class PreferenceUpdate(BaseModel):
    last_frequency_hz: Optional[float] = None
    last_wavelength_m: Optional[float] = None


@app.put("/preferences")
def update_preferences(update: PreferenceUpdate, current_user: dict = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    changes = {k: v for k, v in update.model_dump().items() if v is not None}
    db["user"].update_one({"email": current_user["email"]}, {"$set": {"preferences": changes, "updated_at": datetime.now(timezone.utc)}})
    return {"message": "Preferences updated", "preferences": changes}


# Educational wave content
@app.get("/content/waves", response_model=List[WaveContentSchema])
def get_wave_content():
    # Seed defaults if not present
    defaults = [
        {
            "key": "radio",
            "label": "Radio Waves",
            "min_freq_hz": 3e3,
            "max_freq_hz": 3e9,
            "min_wavelength_m": 1e-1,
            "max_wavelength_m": 1e5,
            "uses": ["Broadcasting", "Communication", "Navigation"],
            "warnings": ["Generally safe at environmental levels"]
        },
        {
            "key": "microwave",
            "label": "Microwaves",
            "min_freq_hz": 3e9,
            "max_freq_hz": 3e11,
            "min_wavelength_m": 1e-3,
            "max_wavelength_m": 1e-1,
            "uses": ["Cooking", "Radar", "Wi‑Fi"],
            "warnings": ["High power exposure can cause heating"]
        },
        {
            "key": "infrared",
            "label": "Infrared",
            "min_freq_hz": 3e11,
            "max_freq_hz": 4e14,
            "min_wavelength_m": 7.5e-7,
            "max_wavelength_m": 1e-3,
            "uses": ["Remote controls", "Thermal imaging"],
            "warnings": ["Prolonged high intensity may cause heating"]
        },
        {
            "key": "visible",
            "label": "Visible Light",
            "min_freq_hz": 4e14,
            "max_freq_hz": 7.5e14,
            "min_wavelength_m": 4e-7,
            "max_wavelength_m": 7.5e-7,
            "uses": ["Human vision", "Photography"],
            "warnings": ["Very bright light can harm eyes"]
        },
        {
            "key": "ultraviolet",
            "label": "Ultraviolet",
            "min_freq_hz": 7.5e14,
            "max_freq_hz": 3e16,
            "min_wavelength_m": 1e-8,
            "max_wavelength_m": 4e-7,
            "uses": ["Sterilization", "Black lights"],
            "warnings": ["Can damage skin and eyes"]
        },
        {
            "key": "xray",
            "label": "X‑Rays",
            "min_freq_hz": 3e16,
            "max_freq_hz": 3e19,
            "min_wavelength_m": 1e-11,
            "max_wavelength_m": 1e-8,
            "uses": ["Medical imaging", "Security scanning"],
            "warnings": ["Ionizing radiation: limit exposure"]
        },
        {
            "key": "gamma",
            "label": "Gamma Rays",
            "min_freq_hz": 3e19,
            "max_freq_hz": 1e23,
            "min_wavelength_m": 1e-16,
            "max_wavelength_m": 1e-11,
            "uses": ["Cancer therapy", "Astrophysics"],
            "warnings": ["Highly penetrating ionizing radiation"]
        }
    ]

    if db is None:
        # Return defaults without persistence if DB not configured
        return defaults

    # Upsert defaults if collection empty
    count = db["wavecontent"].count_documents({})
    if count == 0:
        db["wavecontent"].insert_many(defaults)

    docs = list(db["wavecontent"].find({}, {"_id": 0}))
    return docs


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
