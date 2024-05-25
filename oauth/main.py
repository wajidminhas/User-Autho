from fastapi import FastAPI, Depends, HTTPException
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated

ALGORITHM = "HS256"
SECRET_KEY = "secure with new oauth"





def create_access_token(subject: str, expire_delta : timedelta)-> str:
    expire = datetime.utcnow() + expire_delta
    expire_in_seconds = int(expire.timestamp())
    to_encode = {"expire" : expire_in_seconds, "sub" : str(subject)}
    jwt_endcode = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return jwt_endcode

def decode_access_token(token : str):
    decode_token = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    return decode_token

app : FastAPI = FastAPI()

#  TO CREATE LOGIN SYSTEM 
@app.post("/login")
async def login_request(data_from_client : Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)]):
    

    return {"User Name" : data_from_client.username, "Password" : data_from_client.password}





@app.get("/get_token")
async def get_token(user_name : str):
    expire_access_token = timedelta(minutes=1)

    access_token = create_access_token(subject=user_name, expire_delta=expire_access_token)

    return {"Access Token" : access_token}

@app.get("/decode_token")
async def decode_token(token: str):
    try:
        decode_data = decode_access_token(token)
        print("Decode the Token", decode_data)
        return decode_data
    except JWTError as e:
        return {"error": str(e)}