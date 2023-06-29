import jwt
import os
import requests
from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient
from app.config import settings


url = os.getenv("KEYCLOAK_URL_REALM")
client_id = os.getenv("KEYCLOAK_CLIENT_ID")

jwks_client = PyJWKClient(url)

def decode_token(jwtoken):
    keycloak_realm = requests.get(url)
    keycloak_realm.raise_for_status()
    key_der_base64 = keycloak_realm.json()["public_key"]
    key_der = b64decode(key_der_base64.encode())
    public_key = serialization.load_der_public_key(key_der)
    payload = jwt.decode(jwtoken, public_key, algorithms=["RS256"], 
                         audience=client_id)
    return payload

def get_token_in_cookie(request):
    try:
        return request.cookies.get("auth_token")
    except:
        return None


def get_token_in_header(request):
    try:
        return request.headers.get('Authorization').replace("Bearer ", "") 
    except:
        return None

async def check_origin_is_backend(request):
    try:
        token = get_token_in_header(request)
        if token != settings.BACKEND_SECRET:
            raise HTTPException(status_code=403)
        return
    except Exception as e:
        print(str(e))
        raise HTTPException(status_code=403)

def get_current_token(
    request: Request
) -> dict:
    return get_token_in_cookie(request) or get_token_in_header(request)


def get_current_active_token(
    current_token: str = Depends(get_current_token)
) -> dict:
    if not current_token:
        raise HTTPException(status_code=403, detail="Not authenticated")
    return current_token


async def get_current_user_id(
    current_token: str = Depends(get_current_active_token)
):
    return decode_token(current_token).get("sub")