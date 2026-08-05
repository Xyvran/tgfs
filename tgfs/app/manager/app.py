import asyncio
import logging
import os
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from tgfs.app.fs_cache import gfc
from tgfs.app.utils import split_global_path
from tgfs.config import Config
from tgfs.core import Clients
from tgfs.core.backfill import backfill_mirrors, count_files, create_backfill_task
from tgfs.core.ops import Ops
from tgfs.reqres import MessageRespWithDocument
from tgfs.tasks import task_store

logger = logging.getLogger(__name__)


def create_manager_app(clients: Clients, config: Config) -> FastAPI:
    ops = {channel_id: Ops(client) for channel_id, client in clients.items()}

    def get_name_by_channel_id(channel_id: int) -> str:
        return config.tgfs.metadata[str(channel_id)].name

    app = FastAPI()

    @app.get("/tasks", response_model=List[dict])
    async def get_tasks(
        path: Optional[str] = Query(
            None, description="Filter tasks under specific path"
        )
    ):
        if path is not None:
            tasks = await task_store.get_tasks_under_path(path)
        else:
            tasks = await task_store.get_all_tasks()

        return [task.to_dict() for task in tasks]

    @app.get("/tasks/{task_id}", response_model=dict)
    async def get_task(task_id: str):
        if not (task := await task_store.get_task(task_id)):
            raise HTTPException(status_code=404, detail="Task not found")
        return task.to_dict()

    @app.delete("/tasks/{task_id}")
    async def delete_task(task_id: str):
        """Delete a task."""
        if not await task_store.remove_task(task_id):
            raise HTTPException(status_code=404, detail="Task not found")
        return {"message": "Task deleted successfully"}

    @app.get("/redundancy")
    async def get_redundancy():
        """Redundancy configuration overview, per client."""
        redundancy = config.telegram.redundancy
        return {
            name: {
                "mirrors": (client.mirror_group.channel_keys
                            if client.mirror_group else []),
                "mode": redundancy.mode if redundancy else None,
                "strict": redundancy.strict if redundancy else False,
            }
            for name, client in clients.items()
        }

    @app.post("/redundancy/backfill/{client_name}")
    async def start_backfill(client_name: str, verify: bool = Query(False)):
        """Mirror all pre-existing, unmirrored data of one client.

        Runs in the background; progress is reported through the regular
        /tasks endpoints (type ``mirror_backfill``). ``verify=true``
        additionally checks that recorded mirror copies still exist and
        re-mirrors any that were deleted.
        """
        if (client := clients.get(client_name)) is None:
            raise HTTPException(status_code=404, detail="Unknown client")
        if client.mirror_group is None:
            raise HTTPException(
                status_code=400,
                detail=f"No mirror channels configured for '{client_name}'",
            )

        task_id = await create_backfill_task(client, count_files(client))

        async def run() -> None:
            try:
                await backfill_mirrors(client, verify=verify, task_id=task_id)
            except Exception:
                logger.exception(f"Mirror backfill for '{client_name}' crashed")

        asyncio.get_running_loop().create_task(run())
        return {"task_id": task_id}

    async def get_message(channel_id: int, message_id: int) -> MessageRespWithDocument:
        if str(channel_id) not in config.telegram.private_file_channel:
            raise HTTPException(
                status_code=400,
                detail="The message is not in one of the configured file channels. "
                "Please forward the message to the file channel of your importing location first.",
            )

        client = clients[get_name_by_channel_id(channel_id)]

        message = (await client.message_api.get_messages([message_id]))[0]

        if not message:
            raise HTTPException(
                status_code=404,
                detail=f"Message {message_id} not found in the file channel.",
            )

        if not message.document:
            raise HTTPException(
                status_code=400, detail="The message does not contain a document."
            )

        return MessageRespWithDocument(
            message_id=message.message_id,
            document=message.document,
            text=message.text,
        )

    @app.get("/message/{channel_id}/{message_id}")
    async def get_telegram_message(channel_id: int, message_id: int):
        message = await get_message(channel_id, message_id)

        # Return message info regardless of whether it has a document
        return {
            "id": message.message_id,
            "file_size": message.document.size,
            "caption": message.text or "",
            "mime_type": message.document.mime_type,
        }

    class ImportTelegramMessageData(BaseModel):
        directory: str
        name: str
        channel_id: int
        message_id: int

    @app.post("/import")
    async def import_telegram_message(body: ImportTelegramMessageData):
        message = await get_message(body.channel_id, body.message_id)
        if not body.directory.endswith("/"):
            directory = body.directory + "/"
        else:
            directory = body.directory
        client_name, sub_path = split_global_path(directory)

        if client_name != get_name_by_channel_id(body.channel_id):
            raise HTTPException(
                status_code=400,
                detail=f"The file is not in the channel managing the current folder {client_name}",
            )

        gfc[client_name].reset(f"/{sub_path}")

        await ops[client_name].import_from_existing_file_message(
            message, os.path.join(f"/{sub_path}", body.name)
        )

        return {"message": "Document imported successfully"}

    return app
