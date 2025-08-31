from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
import secrets
import os
from fastapi import HTTPException, status, Request, Depends
from sqlalchemy import select
from schemas import TokenData, TempToken, LoginRequest, Token, RefreshRequest, ErrorResponse
from database import get_db
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from model import Employee
from typing import Dict, Optional
import asyncio

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-strong-secret-key")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "your-refresh-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Shorter for better security
REFRESH_TOKEN_EXPIRE_DAYS = 7
TEMP_TOKEN_EXPIRE_MINUTES = 5

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Token storage
temp_token_store: Dict[str, dict] = {}
active_tokens: Dict[str, dict] = {}  # Store active tokens for quick revocation

class AuthService:
    def __init__(self):
        self.temp_token_expiry = timedelta(minutes=TEMP_TOKEN_EXPIRE_MINUTES)
        self.refresh_token_expiry = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
    def create_temp_token(self, client_ip: str) -> TempToken:
        """Generate IP-based temporary token"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + self.temp_token_expiry

        temp_token_store[token] = {
            "expires_at": expires_at,
            "used": False,
            "ip": client_ip
        }

        # Convert expires_at to ISO string for JSON serialization
        return TempToken(temp_token=token, expires_at=expires_at.isoformat())
    
    def verify_temp_token(self, token: str, client_ip: str) -> bool:
        """Verify temporary token with IP validation"""
        token_data = temp_token_store.get(token)
        
        if not token_data:
            return False
        
        if datetime.utcnow() > token_data["expires_at"]:
            return False
        
        if token_data["used"]:
            return False
        
        # Strict IP validation
        if token_data["ip"] != client_ip:
            return False
            
        return True
    
    def mark_temp_token_used(self, token: str):
        """Mark temporary token as used"""
        if token in temp_token_store:
            temp_token_store[token]["used"] = True
    
    def create_access_token(self, token_data: TokenData, client_ip: str) -> str:
        """Create IP-bound JWT access token"""
        exp = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        payload = token_data.model_dump()
        payload.update({
            "exp": int(exp.timestamp()),  # Store as integer timestamp
            "ip": client_ip,
            "type": "access"
        })
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        
        # Store token in memory
        active_tokens[token] = {
            "empid": token_data.empid,
            "ip": client_ip,
            "exp": int(exp.timestamp()),  # Store as integer timestamp
            "created_at": datetime.utcnow()
        }
        
        return token
    
    def create_refresh_token(self, token_data: TokenData, client_ip: str) -> str:
        """Create IP-bound refresh token"""
        payload = token_data.model_dump()
        payload.update({
            "exp": datetime.utcnow() + self.refresh_token_expiry,
            "ip": client_ip,
            "type": "refresh"
        })
        token = jwt.encode(payload, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
        
        # Store refresh token in memory
        active_tokens[token] = {
            "empid": token_data.empid,
            "ip": client_ip,
            "exp": payload["exp"],
            "created_at": datetime.utcnow()
        }
        
        return token
    
    def verify_access_token(self, token: str, client_ip: str) -> TokenData:
        """Verify access token with strict IP binding"""
        # First check if token exists in active tokens
        if token not in active_tokens:
            raise JWTError("Token not found or revoked")
            
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            self._validate_token_payload(payload, client_ip, "access")
            return TokenData(**{k: v for k, v in payload.items() if k in TokenData.__annotations__})
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ErrorResponse(
                    code=401,
                    detail=f"Invalid token: {str(e)}"
                ).dict()
            )
    
    def verify_refresh_token(self, token: str, client_ip: str) -> TokenData:
        """Verify refresh token with strict IP binding"""
        # First check if token exists in active tokens
        if token not in active_tokens:
            raise JWTError("Token not found or revoked")
            
        try:
            payload = jwt.decode(token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
            self._validate_token_payload(payload, client_ip, "refresh")
            return TokenData(**{k: v for k, v in payload.items() if k in TokenData.__annotations__})
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ErrorResponse(
                    code=401,
                    detail=f"Invalid refresh token: {str(e)}"
                ).dict()
            )
    
    def _validate_token_payload(self, payload: dict, client_ip: str, token_type: str):
        """Validate token payload with strict checks"""
        if payload.get("type") != token_type:
            raise JWTError("Invalid token type")
        
        if datetime.utcnow() > datetime.fromtimestamp(payload["exp"]):
            raise JWTError("Token expired")
        
        if payload.get("ip") != client_ip:
            raise JWTError("IP address changed")
        
        # Validate required claims
        required_claims = ["sub", "role", "empid"]
        if not all(claim in payload for claim in required_claims):
            raise JWTError("Missing required claims")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        return pwd_context.hash(password)
    
    async def authenticate_user(self, db: AsyncSession, username: str, password: str) -> TokenData:
        stmt = select(Employee).where(Employee.username == username)
        result = await db.execute(stmt)
        user = result.scalars().first()
        
        if not user or not self.verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ErrorResponse(
                    code=401,
                    detail="Invalid credentials"
                ).dict()
            )
            
        return TokenData(
            username=user.username,
            role=user.role,
            empid=user.empid
        )

    async def login(self, login_data: LoginRequest, db: AsyncSession, client_ip: str) -> Token:
        """Full login process with IP validation"""
        # Verify temporary token
        if not self.verify_temp_token(login_data.temp_token, client_ip):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ErrorResponse(
                    code=401,
                    detail="Invalid or expired temporary token"
                ).dict()
            )
        print("Temp token verified")
        # Authenticate credentials
        token_data = await self.authenticate_user(db, login_data.username, login_data.password)
        
        # Mark temp token as used
        self.mark_temp_token_used(login_data.temp_token)
        
        # Create tokens
        access_token = self.create_access_token(token_data, client_ip)
        refresh_token = self.create_refresh_token(token_data, client_ip)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    
    def refresh_token(self, refresh_token: str, client_ip: str) -> Token:
        """Refresh access token with IP validation"""
        # Verify refresh token
        token_data = self.verify_refresh_token(refresh_token, client_ip)
        
        # Create new access token
        access_token = self.create_access_token(token_data, client_ip)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,  # Refresh token remains valid
            token_type="bearer"
        )
    
    def set_auth_cookies(self, response, token: Token):
        """Set secure HTTP-only cookies"""
        response.set_cookie(
            key="access_token",
            value=token.access_token,
            httponly=True,
            secure=True,  # Requires HTTPS in production
            samesite="Strict",
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        response.set_cookie(
            key="refresh_token",
            value=token.refresh_token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        )
    
    async def cleanup_expired_tokens(self):
        """Periodically clean expired tokens"""
        while True:
            now = datetime.utcnow()
            
            # Clean temp tokens
            expired_temp = [k for k, v in temp_token_store.items() 
                          if v["expires_at"] < now]
            for token in expired_temp:
                del temp_token_store[token]
            
            # Clean active tokens
            expired_active = [k for k, v in active_tokens.items() 
                            if datetime.fromtimestamp(v["exp"]) < now]
            for token in expired_active:
                del active_tokens[token]
            
            await asyncio.sleep(60 * 5)  # Run every 5 minutes

    def revoke_token(self, token: str):
        """Revoke a token before expiration"""
        if token in active_tokens:
            del active_tokens[token]
            return True
        return False

    async def get_current_user(self, request: Request) -> TokenData:
        """Dependency to get current user from verified token"""
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ErrorResponse(
                    code=401,
                    detail="Missing access token"
                ).dict()
            )
        
        try:
            return self.verify_access_token(token, request.client.host)
        except HTTPException:
            # Try to refresh token
            refresh_token = request.cookies.get("refresh_token")
            if refresh_token:
                try:
                    new_token = self.refresh_token(refresh_token, request.client.host)
                    # Update request with new token
                    request.cookies["access_token"] = new_token.access_token
                    return self.verify_access_token(new_token.access_token, request.client.host)
                except HTTPException:
                    pass
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ErrorResponse(
                    code=401,
                    detail="Invalid or expired credentials"
                ).dict()
            )

    def require_role(self, required_role: str):
        """Dependency to require specific role"""
        async def role_checker(
            current_user: TokenData = Depends(self.get_current_user)
        ):
            if current_user.role != required_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=ErrorResponse(
                        code=403,
                        detail="Insufficient permissions"
                    ).dict()
                )
            return current_user
        return role_checker

# Create singleton instance
auth_service = AuthService()