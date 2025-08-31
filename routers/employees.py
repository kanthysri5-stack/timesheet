from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from schemas import Employee, EmployeeCreate, EmployeeUpdate
from model import Employee as DBEmployee
from auth import auth_service, TokenData
from typing import List

router = APIRouter(
    prefix="/employees",
    tags=["employees"],
    dependencies=[Depends(auth_service.get_current_user)]
)

@router.post("/", response_model=Employee, status_code=status.HTTP_201_CREATED)
def create_employee(
    employee: EmployeeCreate,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.require_role("admin"))
):
    # Check if username already exists
    existing_user = db.query(DBEmployee).filter(
        DBEmployee.username == employee.username
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Hash password
    hashed_password = auth_service.get_password_hash(employee.password)
    
    # Create new employee
    db_employee = DBEmployee(
        firstname=employee.firstname,
        lastname=employee.lastname,
        mail=employee.mail,
        username=employee.username,
        password_hash=hashed_password,
        role=employee.role,
        is_active=True,
        leaves_available=employee.leaves_available if employee.leaves_available else 0
    )
    
    db.add(db_employee)
    db.commit()
    db.refresh(db_employee)
    return db_employee

@router.get("/", response_model=List[Employee])
def get_employees(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.require_role("hr"))
):
    return db.query(DBEmployee).offset(skip).limit(limit).all()

@router.get("/{empid}", response_model=Employee)
def get_employee(
    empid: int,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.get_current_user)
):
    db_employee = db.query(employee).filter(DBEmployee.empid == empid).first()
    if not db_employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Employees can only view their own profile unless HR or admin
    if current_user.role not in ["hr", "admin"] and current_user.empid != empid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own profile"
        )
    
    return db_employee

@router.put("/{empid}", response_model=Employee)
def update_employee(
    empid: int,
    employee: EmployeeUpdate,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.require_role("hr"))
):
    db_employee = db.query(DBEmployee).filter(DBEmployee.empid == empid).first()
    if not db_employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Update fields
    update_data = employee.dict(exclude_unset=True)
    for key, value in update_data.items():
        if key == "password":
            # Hash new password if provided
            setattr(db_employee, "password_hash", auth_service.get_password_hash(value))
        else:
            setattr(db_employee, key, value)
    
    db.commit()
    db.refresh(db_employee)
    return db_employee

@router.delete("/{empid}", status_code=status.HTTP_204_NO_CONTENT)
def delete_employee(
    empid: int,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(auth_service.require_role("admin"))
):
    db_employee = db.query(DBEmployee).filter(DBEmployee.empid == empid).first()
    if not db_employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Soft delete (deactivate) instead of permanent delete
    db_employee.is_active = False
    db.commit()
    return