"""Lazy async database connection management."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from src.config import settings

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def normalize_database_url(url: str) -> str:
    """Normalize Railway/standard Postgres URLs for SQLAlchemy's asyncpg driver."""
    if url.startswith("postgres://"):
        return "postgresql+asyncpg://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url[len("postgresql://"):]
    return url


def get_engine() -> AsyncEngine:
    global _engine, _session_factory
    if not settings.database_url:
        raise RuntimeError("DATABASE_URL is not configured")
    if _engine is None:
        _engine = create_async_engine(
            normalize_database_url(settings.database_url),
            echo=False,
            poolclass=NullPool,
            pool_pre_ping=True,
        )
        _session_factory = async_sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    get_engine()
    if _session_factory is None:
        raise RuntimeError("Database session factory is unavailable")
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with get_session_factory()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    async with get_session_factory()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Initialize the local SQLAlchemy schema safely across multiple workers.

    PostgreSQL's CREATE TABLE IF NOT EXISTS check is not sufficient when two
    Uvicorn workers start simultaneously: both workers can pass the check and
    race while PostgreSQL creates the table's composite type. A transaction-
    independent advisory lock serializes schema initialization for the whole
    database while still allowing normal concurrent application traffic.
    """
    from src.models import Base

    async with get_engine().connect() as connection:
        await connection.execute(
            text("SELECT pg_advisory_lock(hashtext('loystar_mcp_schema_init'))")
        )
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
        finally:
            await connection.execute(
                text("SELECT pg_advisory_unlock(hashtext('loystar_mcp_schema_init'))")
            )


async def check_db() -> None:
    async with get_engine().connect() as connection:
        await connection.execute(text("SELECT 1"))


async def close_db() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
