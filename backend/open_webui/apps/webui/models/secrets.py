import logging
import time
import uuid
from typing import Optional, Text

from open_webui.apps.webui.internal.db import Base, get_db


from open_webui.env import SRC_LOG_LEVELS
from pydantic import BaseModel, ConfigDict
from sqlalchemy import BigInteger, Column, String, JSON, PrimaryKeyConstraint

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MODELS"])


####################
# Secret DB Schema
####################
class Secret(Base):
    __tablename__ = "secret"

    id = Column(Text, unique=True, primary_key=True)
    type = Column(String)
    user_id = Column(String)
    meta = Column(JSON, nullable=True)

    # Unique constraint ensuring (id, user_id) is unique, not just the `id` column
    __table_args__ = (PrimaryKeyConstraint("id", "user_id", name="pk_id_user_id"),)


class SecretModel(BaseModel):
    id: str
    type: str
    user_id: str
    meta: Optional[dict] = None


class SecretForm(BaseModel):
    id: str
    type: str
    user_id: str
    meta: Optional[dict] = None


class SecretTable:
    def insert_new_secret(self, user_id: str, form_data: SecretForm) -> Optional[SecretModel]:
        with get_db() as db:
            try:
                secret = Secret(
                    id=str(uuid.uuid4()),
                    type=form_data.type,
                    user_id=user_id,
                    meta=form_data.meta,
                )

                db.add(secret)
                db.commit()
                db.refresh(secret)

                return SecretModel.from_orm(secret)
            except Exception as e:
                log.exception(f"Failed to insert secret: {e}")
                db.rollback()
                return None

    def get_secrets_by_user_id(self, user_id: str) -> list[SecretModel]:
        with get_db() as db:
            return [
                SecretModel.from_orm(secret)
                for secret in db.query(Secret).filter_by(user_id=user_id).all()
            ]

    def delete_secret_by_id(self, secret_id: str) -> bool:
        with get_db() as db:
            result = db.query(Secret).filter_by(id=secret_id).delete()
            db.commit()
            return result > 0


Secrets = SecretTable()