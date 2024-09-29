import asyncio
import ujson
from typing import Dict
import argparse
from scan_compute.utils.cache import cache as redis_client
from scan_compute.services.scan_processor import Processor
from scan_compute.utils.logging import logger

clog = logger.bind(name="Scan Consumer")

STREAM_NAME = "scan_tasks"
CONSUMER_GROUP = "scan_processors"


async def process_scan(payload: Dict[str, str]):
    logger.info(f"Processing scan for payload: {payload}")
    processor = Processor(
        payload["bucket_name"],
        payload["schema_name"],
        payload["account_id"],
        payload["scan_id"],
        payload["scan_type"],
        payload["cloud_provider"],
    )
    await processor.run()

    # SEND NOTIFICATIONS HERE
    if processor.has_critical_errors:
        logger.error(f"""SCAN FAILED FOR {payload["scan_id"]}""")
    else:
        logger.info(f"""SCAN COMPLETED SUCCESSFULLY FOR {payload["scan_id"]}""")

    # NOTE: this updates client scan report and master account tables
    await processor.update_scan_data()


async def consume_tasks(consumer_name: str):
    clog.info(f"Consumer {consumer_name} started")

    await redis_client.xgroup_create(STREAM_NAME, CONSUMER_GROUP)

    while True:
        try:
            messages = await redis_client.xread_group(
                CONSUMER_GROUP, consumer_name, {STREAM_NAME: ">"}, count=1
            )

            if messages:
                for _, message_list in messages:
                    for message_id, message_data in message_list:
                        try:
                            payload_dict = ujson.loads(message_data["payload"])
                            clog.bind(consumer=consumer_name).info(
                                f"TASK STARTED FOR: {payload_dict['scan_id']}"
                            )

                            await process_scan(payload_dict)

                            await redis_client.xack(
                                STREAM_NAME, CONSUMER_GROUP, message_id
                            )

                        except ujson.JSONDecodeError:
                            clog.bind(consumer=consumer_name).warning(
                                "SKIPPING MESSAGE", message=message_data
                            )
                        except Exception as e:
                            # NOTE: in case of error, we don't acknowledge the message,
                            # so it can be retried later
                            clog.bind(consumer=consumer_name).error(
                                f"ERROR processing message: {str(e)}"
                            )
            else:
                await asyncio.sleep(1)

        except Exception as e:
            clog.bind(consumer=consumer_name).error(f"Error in consume_tasks: {str(e)}")
            await asyncio.sleep(
                5
            )  # NOTE: wait a bit longer before retrying in case of errors


async def main(num_consumers: int):
    clog.info("STARTING SCAN CONSUMERS")
    consumers = [consume_tasks(f"consumer-{i}") for i in range(num_consumers)]
    await asyncio.gather(*consumers)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run scan consumers")
    parser.add_argument(
        "--consumers", type=int, default=1, help="Number of consumers to run"
    )
    args = parser.parse_args()

    asyncio.run(main(args.consumers))
