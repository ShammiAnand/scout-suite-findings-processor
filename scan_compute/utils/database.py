"""Database Utils."""

from __future__ import annotations

import logging
from asyncpg.pool import PoolConnectionProxy
import ujson
from typing import TYPE_CHECKING, Any, List
from scan_compute.utils.logging import logger

import pymongo
import asyncpg

from .config import settings

if TYPE_CHECKING:
    from asyncpg.pool import Pool


class MongoDB:
    _logger = logger.bind(name="Mongo DB")
    _client: pymongo.MongoClient = pymongo.MongoClient(str(settings.MONGODB_DSN))

    @classmethod
    def bulk_insert(
        cls,
        schema_name: str,
        col: str,
        data: List[Any],
    ) -> int:
        """tries to bulk insert into mongo db and returns the inserted count"""
        try:
            cls._logger.debug(f"DB_NAME: shield_{schema_name}")

            db = cls._client[f"shield_{schema_name}"]
            collection = db[col]

            return len(collection.insert_many(data).inserted_ids)

        except Exception as e:
            cls._logger.bind(db=f"shield_{schema_name}").error(e)
            return 0

    @classmethod
    def get_client(cls) -> pymongo.MongoClient:
        return cls._client


class DB:
    _pool: Pool | None = None
    _pool_size: int = 10
    _timeout: float = 30.0  # seconds
    _lifespan: float = 300.0  # seconds
    _logger = logger.bind(name="Postgres DB")

    @classmethod
    async def get_pool(cls) -> Pool:
        if cls._pool is None:
            try:
                cls._pool = await asyncpg.create_pool(
                    min_size=cls._pool_size,
                    max_size=cls._pool_size,
                    host=str(settings.DATABASE_HOST),
                    port=settings.DATABASE_PORT,
                    database=settings.DATABASE_NAME,
                    user=settings.DATABASE_USER_NAME,
                    password=settings.DATABASE_PASSWORD,
                    command_timeout=cls._timeout,
                    max_inactive_connection_lifetime=cls._lifespan,
                )
                if cls._pool is None:
                    raise Exception(
                        "Failed to create connection pool",
                    )
            except Exception as e:
                cls._logger.error(
                    f"Error creating connection pool: {e}",
                )
                raise

        return cls._pool

    @classmethod
    async def fetch_data(
        cls,
        query: str,
        *args,
    ) -> list[dict[str, Any]]:
        pool = await cls.get_pool()
        async with pool.acquire() as conn:
            try:
                result = await conn.fetch(query, *args)
                return [dict(record) for record in result]
            except asyncpg.PostgresError as e:
                cls._logger.error(f"Error executing fetch query: {e}")
                return []

    @classmethod
    async def execute_query(cls, query: str, *args) -> bool:
        pool = await cls.get_pool()
        async with pool.acquire() as conn:
            try:
                await conn.execute(query, *args)
                return True
            except asyncpg.PostgresError as e:
                cls._logger.error(f"Error executing query: {e}")
                return False

    @classmethod
    async def bulk_insert_without_transaction(
        cls, table_name: str, data_list: List[dict]
    ) -> bool:
        """
        Perform bulk insert into PostgreSQL table using asyncpg.
        ----------------------------------------------
        Args:
            table_name (str): Name of the table to insert data into (schema_name."table_name").
            data_list (List[dict]): List of dictionaries, where keys are column names and values are column values.
        Returns:
            bool: True if insertion was successful, False otherwise.
        """
        try:
            pool = await cls.get_pool()
            async with pool.acquire() as conn:
                columns = list(data_list[0].keys())
                insert_statement = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join('$' + str(i+1) for i in range(len(columns)))})"
                values = [
                    [
                        ujson.dumps(row[col])
                        if isinstance(row[col], (dict, list))
                        else row[col]
                        for col in columns
                    ]
                    for row in data_list
                ]
                await conn.executemany(insert_statement, values)

                cls._logger.info(f"INSERTED {len(data_list)} rows into {table_name}")
                return True

        except asyncpg.PostgresError as e:
            cls._logger.bind(table_name=table_name).error(f"while bulk insert: {e}")
            raise

    @classmethod
    async def upsert(
        cls,
        table_name: str,
        data: dict,
        unique_columns: List[str],
        update_columns: List[str] | None = None,
    ) -> bool:
        """
        Perform an upsert operation on a PostgreSQL table.

        Args:
            table_name (str): Name of the table to upsert data into (schema_name."table_name").
            data (dict): Dictionary where keys are column names and values are column values.
            unique_columns (List[str]): List of column names that form the unique constraint.
            update_columns (List[str] | None): List of column names to update if a conflict occurs.
                                            If None, all columns except unique columns will be updated.

        Returns:
            bool: True if upsert was successful, False otherwise.
        """
        try:
            pool = await cls.get_pool()
            async with pool.acquire() as conn:
                columns = list(data.keys())
                values = list(data.values())
                values = [
                    ujson.dumps(v) if isinstance(v, (dict, list)) else v for v in values
                ]

                placeholders = [f"${i+1}" for i in range(len(columns))]

                insert_stmt = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
                conflict_stmt = f"ON CONFLICT ({', '.join(unique_columns)}) DO"

                if update_columns is None:
                    update_columns = [
                        col for col in columns if col not in unique_columns
                    ]

                if update_columns:
                    update_stmt = f"UPDATE SET {', '.join(f'{col} = EXCLUDED.{col}' for col in update_columns)}"
                    query = f"{insert_stmt} {conflict_stmt} {update_stmt}"
                else:
                    query = f"{insert_stmt} {conflict_stmt} NOTHING"

                await conn.execute(query, *values)
                cls._logger.info(f"Upserted 1 row into {table_name}")
                return True

        except asyncpg.PostgresError as e:
            cls._logger.bind(table_name=table_name).error(f"Error during upsert: {e}")
            return False

    @classmethod
    async def bulk_insert(
        cls, table_name: str, data_list: List[dict], conn: PoolConnectionProxy
    ) -> bool:
        """
        Perform bulk insert into PostgreSQL table using asyncpg.
        CANNOT USE THIS WITHOUT A CONN AND TRANSACTION
        ----------------------------------------------
        Args:
            table_name (str): Name of the table to insert data into (schema_name."table_name").
            data_list (List[dict]): List of dictionaries, where keys are column names and values are column values.
        Returns:
            bool: True if insertion was successful, False otherwise.
        """
        try:
            columns = list(data_list[0].keys())
            insert_statement = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join('$' + str(i+1) for i in range(len(columns)))})"
            values = [
                [
                    ujson.dumps(row[col])
                    if isinstance(row[col], (dict, list))
                    else row[col]
                    for col in columns
                ]
                for row in data_list
            ]
            await conn.executemany(insert_statement, values)

            cls._logger.info(f"INSERTED {len(data_list)} rows into {table_name}")
            return True
        except asyncpg.PostgresError as e:
            cls._logger.bind(table_name=table_name).error(f"while bulk insert: {e}")
            raise

    @classmethod
    async def health_check(cls) -> bool:
        try:
            pool = await cls.get_pool()
            async with pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as e:
            cls._logger.error(f"Database health check failed: {e}")
            return False

    @classmethod
    def configure_logging(
        cls,
        log_level: int = logging.DEBUG,
        log_file: str | None = None,
    ):
        """Configure logging for the DB class.

        :param log_level: Logging level (e.g., logging.DEBUG, logging.INFO)
        :param log_file: Optional file path for logging to a file
        """

        # TODO: do these changes wrt structlog
        # cls._logger.setLevel(log_level)

        # Remove existing handlers
        # for handler in cls._logger.handlers[:]:
        #     cls._logger.removeHandler(handler)
        #
        # cls._handler.setLevel(log_level)
        # cls._logger.addHandler(cls._handler)
        #
        # if log_file:
        #     file_handler = logging.FileHandler(log_file)
        #     file_handler.setFormatter(
        #         logging.Formatter(
        #             "[DATABASE] %(asctime)s - %(levelname)s - %(message)s",
        #         ),
        #     )
        #     file_handler.setLevel(log_level)
        #     cls._logger.addHandler(file_handler)
