from sqlalchemy import Column, Integer, String, Boolean, Date, Float, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class Employee(Base):
    __tablename__ = "employees"
    
    empid = Column(Integer, primary_key=True, index=True)
    firstname = Column(String(50), nullable=False)
    lastname = Column(String(50), nullable=False)
    mail = Column(String(100), unique=True, nullable=False)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    leaves_available = Column(Integer, default=0)
    role = Column(String(50), default='employee')
    
    leaves = relationship("Leave", back_populates="employee")
    timesheets = relationship("Timesheet", back_populates="employee")

class Leave(Base):
    __tablename__ = "leaves"
    
    leave_id = Column(Integer, primary_key=True, index=True)
    empid = Column(Integer, ForeignKey("employees.empid"), nullable=False)
    start_date = Column(Date, nullable=False)
    end_date = Column(Date, nullable=False)
    leave_type = Column(String(20), nullable=False)
    status = Column(String(20), default='pending')
    
    employee = relationship("Employee", back_populates="leaves")

class Timesheet(Base):
    __tablename__ = "timesheets"
    
    timesheet_id = Column(Integer, primary_key=True, index=True)
    empid = Column(Integer, ForeignKey("employees.empid"), nullable=False)
    entry_date = Column(Date, nullable=False)
    hours_worked = Column(Float, nullable=False)
    task_description = Column(String)
    project_code = Column(String(20))
    
    employee = relationship("Employee", back_populates="timesheets")