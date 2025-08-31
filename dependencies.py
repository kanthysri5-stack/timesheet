from fastapi import Depends, HTTPException, Request, status
from auth import auth_service
from schemas import TokenData

async def get_current_user(request: Request) -> TokenData:
    """Dependency to get current user from verified token"""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing access token"
        )
    
    try:
        return auth_service.verify_access_token(
            token, 
            request.client.host
        )
    except HTTPException:
        # Try to refresh token
        refresh_token = request.cookies.get("refresh_token")
        if refresh_token:
            try:
                new_token = auth_service.refresh_token(
                    refresh_token,
                    request.client.host
                )
                # Update request with new token
                request.cookies["access_token"] = new_token.access_token
                return auth_service.verify_access_token(
                    new_token.access_token,
                    request.client.host
                )
            except HTTPException:
                pass
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired credentials"
        )

def require_role(role: str):
    """Dependency to require specific role"""
    async def role_checker(user: TokenData = Depends(get_current_user)):
        if user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return user
    return role_checker