from pydantic import BaseModel, EmailStr
from datetime import date, datetime
from typing import Optional, List

class TempToken(BaseModel):
    temp_token: str
    expires_at: datetime

class LoginRequest(BaseModel):
    username: str
    password: str
    temp_token: str

class RefreshRequest(BaseModel):
    refresh_token: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    username: str
    role: str
    empid: int

class EmployeeBase(BaseModel):
    firstname: str
    lastname: str
    mail: EmailStr
    username: str
    role: str = 'employee'

class EmployeeCreate(EmployeeBase):
    password: str

class Employee(EmployeeBase):
    empid: int
    is_active: bool
    leaves_available: int
    
    class Config:
        from_attributes = True

class EmployeeUpdate(BaseModel):
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    mail: Optional[EmailStr] = None
    username: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    leaves_available: Optional[int] = None

class LeaveBase(BaseModel):
    start_date: date
    end_date: date
    leave_type: str
    reason: Optional[str] = None

class LeaveCreate(LeaveBase):
    pass

class Leave(LeaveBase):
    leave_id: int
    empid: int
    status: str = "pending"
    created_at: datetime
    
    class Config:
        from_attributes = True

class LeaveUpdate(BaseModel):
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    leave_type: Optional[str] = None
    reason: Optional[str] = None
    status: Optional[str] = None

class TimesheetBase(BaseModel):
    entry_date: date
    hours_worked: float
    task_description: str
    project_code: Optional[str] = None

class TimesheetCreate(TimesheetBase):
    pass

class Timesheet(TimesheetBase):
    timesheet_id: int
    empid: int
    submitted_at: datetime
    
    class Config:
        from_attributes = True

class TimesheetUpdate(BaseModel):
    entry_date: Optional[date] = None
    hours_worked: Optional[float] = None
    task_description: Optional[str] = None
    project_code: Optional[str] = None

class LeaveBalance(BaseModel):
    empid: int
    annual_leave: int
    sick_leave: int
    personal_leave: int

class SystemHealth(BaseModel):
    database_status: str
    api_status: str
    cache_status: str
    last_checked: datetime

class AuditLog(BaseModel):
    log_id: int
    empid: int
    action: str
    details: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class UserActivity(BaseModel):
    last_login: datetime
    last_action: str
    active_sessions: int

class ErrorResponse(BaseModel):
    detail: str
    code: int
    timestamp: datetime = datetime.now()

class SuccessResponse(BaseModel):
    message: str
    data: Optional[dict] = None
    timestamp: datetime = datetime.now()

class PaginatedResponse(BaseModel):
    items: List
    total: int
    page: int
    page_size: int