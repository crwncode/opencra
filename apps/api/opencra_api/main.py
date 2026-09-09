from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from opencra_api.billing import router as billing_router
from opencra_api.config import settings
from opencra_api.db import engine
from opencra_api.orm import Base
from opencra_api.routes import router


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="OpenCRA API",
    version="0.1.0",
    description="Optional CRA Article 14 control plane. Does not file with ENISA.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.public_app_url, "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)
app.include_router(billing_router)


def run() -> None:
    import uvicorn

    uvicorn.run("opencra_api.main:app", host="0.0.0.0", port=8000, reload=True)
