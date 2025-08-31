from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from schemas import Timesheet, TimesheetCreate
from model import Timesheet as DBTimesheet
from auth import auth_service,TokenData
from datetime import date
from typing import List
from dependencies import get_current_user

router = APIRouter(
    prefix="/timesheets",
    tags=["timesheets"],
    dependencies=[Depends(get_current_user)]
)

@router.post("/", response_model=Timesheet, status_code=status.HTTP_201_CREATED)
def create_timesheet(
    timesheet: TimesheetCreate,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.get_current_user)
):
    # Validate hours
    if timesheet.hours_worked < 0 or timesheet.hours_worked > 24:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Hours worked must be between 0 and 24"
        )
    
    # Create new timesheet entry
    db_timesheet = DBTimesheet(
        empid=current_user.empid,
        entry_date=timesheet.entry_date,
        hours_worked=timesheet.hours_worked,
        task_description=timesheet.task_description,
        project_code=timesheet.project_code
    )
    
    db.add(db_timesheet)
    db.commit()
    db.refresh(db_timesheet)
    return db_timesheet

@router.get("/", response_model=List[Timesheet])
def get_timesheets(
    start_date: date = None,
    end_date: date = None,
    project_code: str = None,
    skip: int = 0,
    limit: int = 9,
    db: Session = Depends(get_db),
    current_user:TokenData = Depends(auth_service.get_current_user)
):
    query = db.query(DBTimesheet)
    
    # Filter based on user role
    if current_user.role not in ["hr", "admin", "manager"]:
        query = query.filter(DBTimesheet.empid == current_user.empid)
    
    # Apply filters
    if start_date:
        query = query.filter(DBTimesheet.entry_date >= start_date)
    if end_date:
        query = query.filter(DBTimesheet.entry_date <= end_date)
    if project_code:
        query = query.filter(DBTimesheet.project_code == project_code)
    
    return query.order_by(DBTimesheet.entry_date.desc()).offset(skip).limit(limit).all()

@router.get("/summary")
def get_timesheet_summary(
    start_date: date,
    end_date: date,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.get_current_user)
):
    # Build base query
    query = db.query(DBTimesheet)
    
    # Filter based on user role
    if current_user.role not in ["hr", "admin", "manager"]:
        query = query.filter(DBTimesheet.empid == current_user.empid)
    
    # Apply date filters
    query = query.filter(DBTimesheet.entry_date >= start_date)
    query = query.filter(DBTimesheet.entry_date <= end_date)
    
    # Execute query
    entries = query.all()
    
    # Calculate summary
    total_hours = sum(entry.hours_worked for entry in entries)
    project_summary = {}
    
    for entry in entries:
        if entry.project_code not in project_summary:
            project_summary[entry.project_code] = 0
        project_summary[entry.project_code] += entry.hours_worked
    
    return {
        "start_date": start_date,
        "end_date": end_date,
        "total_entries": len(entries),
        "total_hours": total_hours,
        "project_summary": project_summary
    }