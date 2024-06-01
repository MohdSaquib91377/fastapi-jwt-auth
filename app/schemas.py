from datetime import datetime
import uuid

from pydantic import BaseModel,EmailStr,constr

class UserBaseSchema(BaseModel):
    name: str
    email: EmailStr


    class Config:
        orm_mode = True

class CreateUserSchema(UserBaseSchema):
    password: constr(min_length=8)
    is_verified: bool = False

class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class UserResponseSchema(UserBaseSchema):
    id: int
    uid: uuid.UUID
    created_at: datetime
    updated_at: datetime