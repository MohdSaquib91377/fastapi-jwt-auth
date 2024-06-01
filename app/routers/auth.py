from datetime import timedelta
from fastapi import APIRouter, Request, Response, status, Depends, HTTPException
from pydantic import EmailStr

from app import oauth2
from .. import schemas, models, utils
from sqlalchemy.orm import Session
from .. database import get_db
from app.oauth2 import AuthJWT
from .. config import settings


router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


@router.post('/register',status_code=status.HTTP_201_CREATED)
async def create_user(payload: schemas.CreateUserSchema,db: Session = Depends(get_db)):
    # TODO: check user already exists
    db_query = db.query(models.User).filter(models.User.email == EmailStr(payload.email)) 
    user = db_query.first()
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Account already exist")
    
    # TODO: hash user password
    payload.password = utils.hash_password(payload.password)
    payload.is_verified = True
    payload.email = EmailStr(payload.email.lower())
    new_user = models.User(**payload.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post('/login')
def login(payload: schemas.LoginUserSchema,response: Response,db: Session = Depends(get_db),Authorize: AuthJWT = Depends()):
    # TODO: check user is exist
    user = db.query(models.User).filter(models.User.email == EmailStr(payload.email.lower())).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail='Incorrect email or password')
    # TODO: check user has verified
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='please verify your email')

    # TODO: check password is valid
    if not utils.verify_password(payload.password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail='Incorrect email or password')
   
    # TODO: create access token
    access_token = Authorize.create_access_token(
        subject=str(user.id),expires_time=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRES_IN)
    )

    # TODO: create refresh token
    refresh_token = Authorize.create_refresh_token(
        subject=str(user.id),expires_time=timedelta(minutes=settings.REFRESH_TOKEN_EXPIRES_IN)
    )
    # TODO: store access token and refresh token in cookies
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token,
                        REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    # TODO: send both access
    return {"status":"success","access_token":access_token}

@router.post('/refresh')
def refresh_token(request: Request,response: Response, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    try:
        # TODO: check refresh token passs
        Authorize.jwt_refresh_token_required()

        # TODO: Read user id 
        user_id = Authorize.get_jwt_subject()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not refresh access token")

        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail = 'The user belonging to this token no logger exist')

        access_token = Authorize.create_access_token(subject=str(user.id),expires_time=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRES_IN))
    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail='please provide refresh token')
        
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail=error)
    response.set_cookie('access_token',access_token,ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in','True',ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')
    return {"access_token":access_token}

@router.get('/logout',status_code=status.HTTP_200_OK)
def logout(response:Response,Authorize: AuthJWT = Depends(),db: Session = Depends(get_db),user_id: str = Depends(oauth2.require_user)):
    Authorize.unset_jwt_cookies()
    response.set_cookie("logged_in","",-1)

    return {"status": "success"}

@router.get('/me',response_model=schemas.UserResponseSchema)
def get_me(db: Session = Depends(get_db),user_id: str = Depends(oauth2.require_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    return user