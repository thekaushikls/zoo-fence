from pydantic import BaseModel, Field
from typing import Optional
from . import utils

class User(BaseModel):
    email: str
    username: str
    first_name:  Optional[str] = None
    last_name:  Optional[str] = None
    password: Optional[str] = None

    @classmethod
    def from_mongo(cls, data: dict):
        data = utils.map_mongo_id(data)
        return cls(**data)
