from sqlalchemy import Column, TIMESTAMP, String,Boolean,Text,ForeignKey,Integer
from sqlalchemy.orm import relationship

from .base import Base


class Organization(Base):
    name = Column(String,nullable=False)
    owner = relationship('User',back_populates="orgnization")
    

class User(Base):
    name = Column(String,nullable=False)
    email = Column(String,nullable=False,unique=True)
    password = Column(String,nullable=False)
    is_verified = Column(Boolean,nullable=False,server_default='False')
    orgnization_id = Column(Integer,ForeignKey('organizations.id'))
    orgnization = relationship('Organization',back_populates="owner")

