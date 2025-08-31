from fastapi import FastAPI, Request, Depends, HTTPException,Form
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from auth import auth_service
from database import get_db, engine, Base
from routers import employees, leaves, timesheets
from schemas import LoginRequest, Token, RefreshRequest
from sqlalchemy.orm import Session
import os
import asyncio
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from pathlib import Path
from datetime import datetime, timedelta
import random
import string

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
password_reset_data = {}
# Setup templates and static files
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "app" / "templates")

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    asyncio.create_task(auth_service.cleanup_expired_tokens())

# Public endpoints
PUBLIC_PATHS = ["/", "/login", "/auth/login", "/auth/refresh", "/static"]

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Enhanced security middleware with IP binding"""
    # Skip security for public paths
    if any(request.url.path.startswith(path) for path in PUBLIC_PATHS):
        return await call_next(request)
    
    # Extract token from cookies
    token = request.cookies.get("access_token")
    client_ip = request.client.host
    
    if token:
        try:
            # Verify token with IP binding
            token_data = auth_service.verify_access_token(token, client_ip)
            request.state.user = token_data
            
            # Set security headers
            response = await call_next(request)
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            return response
        except HTTPException as e:
            if e.status_code == 401:
                # Token needs refresh
                refresh_token = request.cookies.get("refresh_token")
                if refresh_token:
                    try:
                        new_tokens = auth_service.refresh_token(refresh_token, client_ip)
                        response = RedirectResponse(request.url)
                        auth_service.set_auth_cookies(response, new_tokens)
                        return response
                    except HTTPException:
                        pass
    
    # Redirect to login with new temp token
    temp_token = auth_service.create_temp_token(client_ip)
    redirect_url = request.url_for("login_page").include_query_params(
        temp_token=temp_token.temp_token,
        next=str(request.url)
    )
    return RedirectResponse(url=redirect_url)

@app.get("/", response_class=HTMLResponse, name="login_page")
@limiter.limit("10/minute")
async def login_page(request: Request):
    """Serve login page with IP-based temporary token"""
    client_ip = request.client.host
    temp_token = auth_service.create_temp_token(client_ip)
    
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "temp_token": temp_token.temp_token
        }
    )

@app.get("/login", include_in_schema=False)
async def redirect_to_login():
    """Redirect /login to root login page"""
    return RedirectResponse(url="/")

@app.post("/auth/login", response_model=Token)
@limiter.limit("5/minute")
async def login_endpoint(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Login endpoint with IP validation"""
    client_ip = request.client.host
    token = auth_service.login(login_data, db, client_ip)
    
    # Set secure cookies
    response = RedirectResponse(url=request.query_params.get("next", "/dashboard"), status_code=303)
    auth_service.set_auth_cookies(response, token)
    return response

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    """Serve single-page password reset"""
    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request}
    )

@app.post("/auth/forgot-password")
async def handle_password_reset(
    request: Request,
    email: str = Form(...),
    otp: str = Form(None),
    new_password: str = Form(None),
    confirm_password: str = Form(None),
    db: Session = Depends(get_db)  # Now using the imported Session
):
    """Handle the entire password reset flow in one endpoint"""
    client_ip = request.client.host
    
    # Step 1: Initial request (generate and store OTP)
    if not otp and not new_password:
        # Generate 6-digit OTP
        reset_otp = ''.join(random.choices(string.digits, k=6))
        
        # Store OTP with expiration (10 minutes)
        password_reset_data[email] = {
            "otp": reset_otp,
            "expires_at": datetime.utcnow() + timedelta(minutes=10),
            "ip": client_ip
        }
        
        print(f"OTP for {email}: {reset_otp}")  # For local testing
        
        return templates.TemplateResponse(
            "forgot_password.html",
            {
                "request": request,
                "email": email,
                "show_otp": True,
                "message": f"OTP sent to {email} (check console for local testing)"
            }
        )
    
    # Step 2: OTP verification
    if otp and not new_password:
        # Validate OTP
        stored_data = password_reset_data.get(email)
        
        if not stored_data:
            return templates.TemplateResponse(
                "forgot_password.html",
                {
                    "request": request,
                    "email": email,
                    "show_otp": True,
                    "error": "Invalid request. Please start over."
                }
            )
        
        if datetime.utcnow() > stored_data["expires_at"]:
            return templates.TemplateResponse(
                "forgot_password.html",
                {
                    "request": request,
                    "email": email,
                    "show_otp": True,
                    "error": "OTP has expired. Please request a new one."
                }
            )
        
        if stored_data["otp"] != otp:
            return templates.TemplateResponse(
                "forgot_password.html",
                {
                    "request": request,
                    "email": email,
                    "show_otp": True,
                    "error": "Invalid OTP. Please try again."
                }
            )
        
        # OTP is valid, show password fields
        return templates.TemplateResponse(
            "forgot_password.html",
            {
                "request": request,
                "email": email,
                "otp": otp,
                "show_password": True,
                "message": "OTP verified. Please enter your new password."
            }
        )
    
    # Step 3: Password reset
    if new_password and confirm_password:
        # Validate passwords match
        if new_password != confirm_password:
            return templates.TemplateResponse(
                "forgot_password.html",
                {
                    "request": request,
                    "email": email,
                    "otp": otp,
                    "show_password": True,
                    "error": "Passwords do not match."
                }
            )
        
        # Find user by email
        user = db.query(auth_service.Employee).filter(auth_service.Employee.mail == email).first()
        if not user:
            return templates.TemplateResponse(
                "forgot_password.html",
                {
                    "request": request,
                    "email": email,
                    "show_otp": True,
                    "error": "No account found with that email."
                }
            )
        
        # Update password
        user.password_hash = auth_service.get_password_hash(new_password)
        db.commit()
        
        # Clear reset data
        if email in password_reset_data:
            del password_reset_data[email]
        
        return templates.TemplateResponse(
            "forgot_password.html",
            {
                "request": request,
                "success": True,
                "message": "Password reset successful! You can now log in."
            }
        )
    
    # Invalid request
    return templates.TemplateResponse(
        "forgot_password.html",
        {
            "request": request,
            "error": "Invalid request. Please start over."
        }
    )
# Other endpoints remain the same...

# Include routers
app.include_router(employees.router, dependencies=[Depends(auth_service.get_current_user)])
app.include_router(leaves.router, dependencies=[Depends(auth_service.get_current_user)])
app.include_router(timesheets.router, dependencies=[Depends(auth_service.get_current_user)])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=8000)