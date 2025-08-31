from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from schemas import Leave, LeaveCreate
from model import Leave as DBLeave, Employee
from auth import  TokenData
from datetime import date
from typing import List
from auth import auth_service, TokenData

router = APIRouter(
    prefix="/leaves",
    tags=["leaves"],
    dependencies=[Depends(auth_service.get_current_user)]
)

@router.post("/", response_model=Leave, status_code=status.HTTP_201_CREATED)
def create_leave(
    leave: LeaveCreate,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.get_current_user)
):
    # Calculate leave duration
    duration = (leave.end_date - leave.start_date).days + 1
    
    # Get employee
    db_employee = db.query(Employee).filter(Employee.empid == current_user.empid).first()
    if not db_employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Check leave balance
    if db_employee.leaves_available < duration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Insufficient leave balance. Available: {db_employee.leaves_available}, Requested: {duration}"
        )
    
    # Create new leave request
    db_leave = DBLeave(
        empid=current_user.empid,
        start_date=leave.start_date,
        end_date=leave.end_date,
        leave_type=leave.leave_type,
        status="pending"
    )
    
    db.add(db_leave)
    db.commit()
    db.refresh(db_leave)
    return db_leave

@router.get("/", response_model=List[Leave])
def get_leaves(
    status: str = None,
    start_date: date = None,
    end_date: date = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.get_current_user)
):
    query = db.query(DBLeave)
    
    # Filter based on user role
    if current_user.role not in ["hr", "admin"]:
        query = query.filter(DBLeave.empid == current_user.empid)
    
    # Apply filters
    if status:
        query = query.filter(DBLeave.status == status)
    if start_date:
        query = query.filter(DBLeave.start_date >= start_date)
    if end_date:
        query = query.filter(DBLeave.end_date <= end_date)
    
    return query.offset(skip).limit(limit).all()

@router.put("/{leave_id}/approve", response_model=Leave)
def approve_leave(
    leave_id: int,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.require_role("hr"))
):
    db_leave = db.query(DBLeave).filter(DBLeave.leave_id == leave_id).first()
    if not db_leave:
        raise HTTPException(status_code=404, detail="Leave request not found")
    
    if db_leave.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only pending leave requests can be approved"
        )
    
    # Get employee
    db_employee = db.query(Employee).filter(Employee.empid == db_leave.empid).first()
    if not db_employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Calculate leave duration
    duration = (db_leave.end_date - db_leave.start_date).days + 1
    
    # Deduct from leave balance
    if db_employee.leaves_available < duration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Employee doesn't have sufficient leave balance"
        )
    
    db_employee.leaves_available -= duration
    db_leave.status = "approved"
    
    db.commit()
    db.refresh(db_leave)
    return db_leave

@router.put("/{leave_id}/reject", response_model=Leave)
def reject_leave(
    leave_id: int,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.require_role("hr"))
):
    db_leave = db.query(DBLeave).filter(DBLeave.leave_id == leave_id).first()
    if not db_leave:
        raise HTTPException(status_code=404, detail="Leave request not found")
    
    if db_leave.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only pending leave requests can be rejected"
        )
    
    db_leave.status = "rejected"
    db.commit()
    db.refresh(db_leave)
    return db_leave