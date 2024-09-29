"""Cache utils."""

from __future__ import annotations
from typing import Any, Optional
import pickle

import redis
from redis.asyncio import Redis as AsyncRedis

from scan_compute.utils.config import get_settings

app_config = get_settings()


class CacheService:
    def __init__(self):
        self.sync_redis = redis.Redis(
            host=app_config.CACHE_HOST,
            port=app_config.CACHE_PORT,
            db=0,
            decode_responses=False,
        )
        self.async_redis = AsyncRedis(
            host=app_config.CACHE_HOST,
            port=app_config.CACHE_PORT,
            db=0,
            decode_responses=True,  # Set to True for Redis Streams
        )

    def set(
        self, key: str, value: Any, timeout: Optional[int] = 3600 * 24 * 7
    ) -> None:  # NOTE: default timeout is 7 days
        pickled_value = pickle.dumps(value)
        if timeout is not None:
            self.sync_redis.setex(key, timeout, pickled_value)
        else:
            self.sync_redis.set(key, pickled_value)

    def get(self, key: str) -> Any | None:
        pickled_value = self.sync_redis.get(key)
        if pickled_value is None:
            return None
        try:
            return pickle.loads(pickled_value)  # type: ignore
        except pickle.UnpicklingError:
            return pickled_value

    def publish(self, channel: str, message: str):
        return self.sync_redis.publish(channel, message)

    def subscribe(self, channel: str):
        pubsub = self.sync_redis.pubsub()
        pubsub.subscribe(channel)
        return pubsub

    async def xgroup_create(
        self, stream: str, group: str, id: str = "$", mkstream: bool = True
    ):
        try:
            await self.async_redis.xgroup_create(stream, group, id, mkstream=mkstream)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def xread_group(
        self,
        group: str,
        consumer: str,
        streams: dict,
        count: int = 1,
        block: int = 0,
    ):
        return await self.async_redis.xreadgroup(
            group, consumer, streams, count=count, block=block
        )

    async def xack(self, stream: str, group: str, *ids):
        return await self.async_redis.xack(stream, group, *ids)

    async def xadd(self, stream: str, fields: dict, id: str = "*", maxlen=None):
        return await self.async_redis.xadd(stream, fields, id=id, maxlen=maxlen)


cache = CacheService()
