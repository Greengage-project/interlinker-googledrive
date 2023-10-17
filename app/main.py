import json
import os
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
    status,
    Body,
    BackgroundTasks
)
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.cors import CORSMiddleware

import app.crud as crud
from app import deps
from app.config import settings
from app.database import (
    AsyncIOMotorCollection,
    close_mongo_connection,
    connect_to_mongo,
    get_collection,
)
from app.google import delete_file, get_files, set_public
from app.googleservice import close_google_connection, connect_to_google, get_service
from app.info import info_data
from app.model import (
    AssetBasicDataSchema,
    AssetCreateSchema,
    mime_type_options,
    mime_types,
)
from googleapiclient.errors import HttpError

domainfo = {
    "PROTOCOL": settings.PROTOCOL,
    "SERVER_NAME": settings.SERVER_NAME,
    "BASE_PATH": settings.BASE_PATH,
    "COMPLETE_SERVER_NAME": settings.COMPLETE_SERVER_NAME
}
app = FastAPI(
    title="Googledrive interlinker API", openapi_url=f"/openapi.json", docs_url="/docs", root_path=settings.BASE_PATH
)
app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("shutdown", close_mongo_connection)
app.add_event_handler("startup", connect_to_google)
app.add_event_handler("shutdown", close_google_connection)


templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

mainrouter = APIRouter()


@mainrouter.get("/")
def main():
    return RedirectResponse(url=f"{settings.BASE_PATH}/docs")


@mainrouter.get("/info")
def main():
    return info_data


@mainrouter.get("/healthcheck")
def healthcheck():
    return True



# Custom endpoints (have a /api/v1 prefix)
customrouter = APIRouter()

@customrouter.post("/assets/empty", response_description="Asset JSON", status_code=201)
async def create_empty_asset(asset_in: AssetCreateSchema, collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):
    #print('-create empty asset function')
    mime_type = asset_in.mime_type
    name = asset_in.name
    if mime_type in mime_type_options:
        mime = mime_types[mime_type]
        return await crud.create_empty(collection, service, mime, name)
    raise HTTPException(
        status_code=400, detail=f"Mime type {mime_type} not in {mime_type_options}")


@customrouter.get(
    "/assets", response_description="List all assets"
)
async def list_assets(collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):
    #print('-lista los assets function')
    return await crud.get_all(collection, service)


@customrouter.get(
    "/assets/{id}", response_description="Asset JSON"
)
async def show_asset(id: str, collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):
    
    #print('-show asset function')
    asset = await crud.get(collection, service, id)
    if asset is not None:
        return asset

    raise HTTPException(status_code=404, detail=f"Asset {id} not found")


@customrouter.post(
    "/assets/{id}/persist", response_description="Persist a temporal asset"
)
async def persist_asset(id: str, collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):
    #print('-persist asset function')
    if (asset := await crud.get(collection, service, id)):
        if asset["temporal"]:
            return await crud.update(collection, service, id, {"temporal": False})
        return asset
    raise HTTPException(status_code=404, detail=f"Asset {id} not found")

# TODO: Task to remove unused files


@customrouter.get("/files/real")
async def get_real_assets(service=Depends(get_service)):
    nextPageToken, files = get_files(service, 1000)
    return JSONResponse(status_code=status.HTTP_200_OK, content=files)

@customrouter.get("/files/set_public")
async def set_public_files(service=Depends(get_service)):
    nextPageToken, files = get_files(service, 1000)
    for file in files:
        try:
           #print("Setting", file.get("id"), "public")
            set_public(service, file.get("id") )
        except:
            pass
    return JSONResponse(status_code=status.HTTP_200_OK, content=files)

@customrouter.get("/files/delete")
async def delete_unused_files(collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):
    #print('-Delete the files function')
    assets = await crud.get_all(collection, service)
    assets_ids = [asset["_id"] for asset in assets]
    nextPageToken, files = get_files(service)
    files_ids = [file["id"] for file in files]
    matches = [el for el in files_ids if el not in assets_ids]
    for id in matches:
        delete_file(service, id)
    return JSONResponse(status_code=status.HTTP_200_OK)

integrablerouter = APIRouter()


@integrablerouter.post("/assets", response_description="Add new asset", status_code=201)
async def create_asset(file: Optional[UploadFile] = File(...), collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):
    #print('-create asset function')
    file_name = os.getcwd()+"/tmp/"+file.filename.replace(" ", "-")
    
    #print('-the filename is')
   #print(file_name)

    with open(file_name, 'wb+') as f:
        f.write(file.file.read())
        f.close()
    # optional because needs confirmation
    #print('-Try ti save it in the server:')

    return await crud.create(collection, service, file_name)


@integrablerouter.get(
    "/assets/instantiate", response_description="GUI for asset creation"
)
async def instantiate_asset(request: Request):
    return templates.TemplateResponse("instantiator.html", {"request": request, "BASE_PATH": settings.BASE_PATH, "DOMAIN_INFO": json.dumps(domainfo)})


@integrablerouter.get(
    "/assets/{id}", response_description="Asset JSON", response_model=AssetBasicDataSchema
)
async def asset_data(id: str, collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):#, user_id=Depends(deps.get_current_user_id)):
    #print('-asset_data function')
    if (asset := await crud.get(collection, service, id)) is not None:
        return asset
    raise HTTPException(status_code=404, detail=f"Asset {id} not found")


@integrablerouter.delete("/assets/{id}", response_description="No content")
async def delete_asset(request: Request, id: str, collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):
    #print('-Delete the file again')
    await deps.check_origin_is_backend(request)
    
    # do not remove only_backend
    
    if await crud.get_only_db(collection, id) is not None:
        try:
            delete_file(service=service, id=id)
        except Exception as e:
            print(str(e))
        delete_result = await crud.delete(collection, id)
        if delete_result.deleted_count == 1:
            return HTTPException(status_code=204)

    raise HTTPException(status_code=404, detail=f"Asset {id} not found")


@integrablerouter.get(
    "/assets/{id}/download", response_description="Asset file"
)
async def download_asset(id: str, collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service)):
    #print('-download asset function')
    if (asset := await crud.get(collection, service, id)) is not None:
        if "webContentLink" in asset:
            return RedirectResponse(url=asset["webContentLink"])
        return JSONResponse({"error": "Could not download this resource. Try again later."})
    raise HTTPException(status_code=404, detail=f"Asset {id} not found")

@integrablerouter.get(
    "/assets/{id}/view", response_description="GUI for interaction with asset"
)
async def asset_viewer(id: str, collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service), user_id=Depends(deps.get_current_user_id)):
    #print('-asset viewer function')
    asset = await crud.get(collection, service, id)
    if asset is not None:
        return RedirectResponse(url=asset["webViewLink"])

    raise HTTPException(status_code=404, detail=f"Asset {id} not found")

@integrablerouter.post(
    "/assets/{id}/clone", response_description="Asset JSON", status_code=201, response_model=AssetBasicDataSchema
)
async def clone_asset(id: str, justRead: str='False', collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service), user_id=Depends(deps.get_current_user_id)):
    #print('-Clone asset function')
    #print('-The value of justRead is:',justRead)
    #print('-The id is:')
   #print(id)
    #print('-The collection is:')
   #print(collection)
    #print('-The service is:')
   #print(service)

   #print('-Trata de encontrarlo en la base de datos(debe estar para poder clonarlo)')
    datosbyId=await crud.get_FileInfo(collection, service, id)
   #print('-Los datos son: ',datosbyId)

    if datosbyId is not None:
        if(justRead=='True'):
           #print('-Cloning with just read option')
            #Clone with read only assets (Used when publish in catalogue):
            return await crud.clone_readonly(collection, service, id)    
        else:
           #print('-Cloning with read and write options')
            return await crud.clone(collection, service, id)
            
    raise HTTPException(status_code=404, detail=f"Asset {id} not found")



@integrablerouter.post(
    "/assets/{id}/sync_users", response_description="Asset JSON", status_code=200
)
async def sync_users(id: str, request: Request, collection: AsyncIOMotorCollection = Depends(get_collection), service=Depends(get_service), payload: list = Body(...)):
   #print(request.client.host)
   #print('-prefix')
   #print(settings.API_V1_STR)
    
    # print(request.client.host)
    # return await crud.sync_users(collection=collection, service=service, file_id=id, users_info=payload)
    return True


app.include_router(mainrouter, tags=["main"])
app.include_router(integrablerouter, tags=["Integrable"])
app.include_router(customrouter, prefix=settings.API_V1_STR, tags=["Custom endpoints"])
