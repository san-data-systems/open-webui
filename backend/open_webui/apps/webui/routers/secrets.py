from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, status

from open_webui.apps.webui.models.secrets import (
    SecretModel,
    SecretTable,
    SecretForm,
)
from open_webui.constants import ERROR_MESSAGES
from open_webui.utils.utils import get_admin_user, get_verified_user
from open_webui.utils.access_control import has_access, has_permission

router = APIRouter()

############################
# GetSecrets
############################


@router.get("/", response_model=List[SecretModel])
async def get_secrets(user=Depends(get_verified_user)):
    if user.role == "admin":
        secrets = SecretTable.get_secrets()
    else:
        secrets = SecretTable.get_secrets_by_user_id(user.id)
    return secrets


############################
# GetSecretById
############################


@router.get("/{id}", response_model=Optional[SecretModel])
async def get_secret_by_id(id: str, user=Depends(get_verified_user)):
    secret = SecretTable.get_secret_by_id(id)
    if secret:
        if (
            user.role == "admin"
            or secret.user_id == user.id
            or has_access(user.id, "read", secret.meta)
        ):
            return secret
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.UNAUTHORIZED,
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# CreateNewSecret
############################


@router.post("/create", response_model=Optional[SecretModel])
async def create_new_secret(
    form_data: SecretForm, user=Depends(get_verified_user)
):
    if user.role != "admin" and not has_permission(
        user.id, "secret.create", user.permissions
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    try:
        secret = SecretTable.insert_new_secret(user.id, form_data)
        if secret:
            return secret
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error creating secret"),
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(str(e)),
        )


############################
# UpdateSecretById
############################


@router.post("/{id}/update", response_model=Optional[SecretModel])
async def update_secret_by_id(
    id: str, form_data: SecretForm, user=Depends(get_verified_user)
):
    """
    Update the name (type) of an existing secret by its ID.
    Only the owner or an admin can update the secret.
    """
    # Fetch the secret by ID
    secret = SecretTable.get_secret_by_id(id)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    # Check authorization
    if secret.user_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    # Update only the 'type' (secret name)
    try:
        updated_secret = SecretTable.update_secret_name_by_id(id, form_data.name)
        if updated_secret:
            return updated_secret
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error updating secret name"),
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(str(e)),
        )


############################
# DeleteSecretById
############################


@router.delete("/{id}/delete", response_model=bool)
async def delete_secret_by_id(id: str, user=Depends(get_verified_user)):
    secret = SecretTable.get_secret_by_id(id)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if secret.user_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    success = SecretTable.delete_secret_by_id(id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT("Error deleting secret"),
        )
    return success