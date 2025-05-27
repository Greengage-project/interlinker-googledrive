from pydantic import BaseModel, Field
from typing import List, Optional
import datetime
from app.config import settings
from pydantic import validator

fields = "id, name, webContentLink, webViewLink, thumbnailLink, version, mimeType, size, iconLink, createdTime, modifiedTime"

mime_types = {
    "docs": "application/vnd.google-apps.document",
    "spreadsheet": "application/vnd.google-apps.spreadsheet",
    "drawing": "application/vnd.google-apps.drawing",
    "file": "application/vnd.google-apps.file",
    "folder": "application/vnd.google-apps.folder",
    "form": "application/vnd.google-apps.form",
    "fusiontable": "application/vnd.google-apps.fusiontable",
    "map": "application/vnd.google-apps.map",
    "slide": "application/vnd.google-apps.presentation",
    "script": "application/vnd.google-apps.script",
    # "site": "application/vnd.google-apps.site",
    # "jamboard": "application/vnd.google-apps.jam",
}
mime_type_options = mime_types.keys()


class AssetCreateSchema(BaseModel):
    mime_type: str
    name: str


class AssetBasicDataSchema(BaseModel):
    id: str
    name: str
    iconLink: str = Field(alias='icon')
    createdTime: datetime.datetime = Field(alias='created_at')
    modifiedTime: Optional[datetime.datetime] = Field(alias='updated_at')

    class Config:
        allow_population_by_field_name = True

    """
    @validator('viewLink', always=True)
    def view_link(cls, name, values):
        asset_id = values["id"]
        return settings.COMPLETE_SERVER_NAME + f"/assets/{asset_id}/view"

    @validator('editLink', always=True)
    def edit_link(cls, name, values):
        asset_id = values["id"]
        return settings.COMPLETE_SERVER_NAME + f"/assets/{asset_id}/edit"
    
    @validator('cloneLink', always=True)
    def clone_link(cls, name, values):
        asset_id = values["id"]
        return settings.COMPLETE_SERVER_NAME + f"/assets/{asset_id}/clone"
    viewLink: Optional[str]
    editLink: Optional[str]
    cloneLink: Optional[str]
    """
