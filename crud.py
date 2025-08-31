from sqlalchemy.orm import Session

from auth import get_password_hash
from . import models, schemas

# Employee CRUD
def get_employee(db: Session, empid: int):
    return db.query(models.Employee).filter(models.Employee.empid == empid).first()

def get_employee_by_username(db: Session, username: str):
    return db.query(models.Employee).filter(models.Employee.username == username).first()

def get_employees(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Employee).offset(skip).limit(limit).all()

def create_employee(db: Session, employee: schemas.EmployeeCreate):
    hashed_password = get_password_hash(employee.password)
    db_employee = models.Employee(
        firstname=employee.firstname,
        lastname=employee.lastname,
        mail=employee.mail,
        username=employee.username,
        password_hash=hashed_password,
        role=employee.role
    )
    db.add(db_employee)
    db.commit()
    db.refresh(db_employee)
    return db_employee

def update_employee(db: Session, empid: int, employee: schemas.EmployeeUpdate):
    db_employee = get_employee(db, empid)
    if not db_employee:
        return None
    
    update_data = employee.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_employee, key, value)
    
    db.commit()
    db.refresh(db_employee)
    return db_employee

# Leave CRUD
def create_leave(db: Session, leave: schemas.LeaveCreate, empid: int):
    db_leave = models.Leave(**leave.dict(), empid=empid)
    db.add(db_leave)
    db.commit()
    db.refresh(db_leave)
    return db_leave

def get_leaves(db: Session, empid: int, skip: int = 0, limit: int = 100):
    return db.query(models.Leave).filter(models.Leave.empid == empid).offset(skip).limit(limit).all()

# Timesheet CRUD
def create_timesheet(db: Session, timesheet: schemas.TimesheetCreate, empid: int):
    db_timesheet = models.Timesheet(**timesheet.dict(), empid=empid)
    db.add(db_timesheet)
    db.commit()
    db.refresh(db_timesheet)
    return db_timesheet

def get_timesheets(db: Session, empid: int, skip: int = 0, limit: int = 100):
    return db.query(models.Timesheet).filter(models.Timesheet.empid == empid).offset(skip).limit(limit).all()