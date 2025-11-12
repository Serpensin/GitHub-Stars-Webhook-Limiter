# bulk_create_keys.py
import time
from datetime import timedelta
from multiprocessing import Event, Process, Queue
from queue import Empty

import requests

BASE_URL = "http://127.0.0.1:5000"

# Load API key from environment variable for security
API_KEY = "9HZ7wknntLZXEzGYyRrpZYPoySwv5jTm3r4odOuZmVI"
TOTAL_KEYS = 100_000
PERMISSION = 42
# Match Gunicorn config: 4 workers * 100 connections = 400 total capacity
# Use fewer workers than server capacity to avoid overwhelming it
NUM_WORKERS = 10  # Number of parallel worker processes


def format_time(seconds):
    """Format seconds into a readable time string."""
    if seconds < 0:
        return "N/A"
    return str(timedelta(seconds=int(seconds)))


def worker(worker_id, task_queue, result_queue, stop_event):
    """Worker process that creates API keys."""
    headers = {"Authorization": f"Bearer {API_KEY}"}

    while not stop_event.is_set():
        try:
            # Get task with timeout to check stop_event periodically
            key_index = task_queue.get(timeout=0.1)

            start_time = time.time()
            success = False

            try:
                resp = requests.post(
                    f"{BASE_URL}/admin/api/keys",
                    json={
                        "name": f"Bulk_Test_{key_index}",
                        "permissions": PERMISSION,
                        "rate_limit": 100,
                    },
                    headers=headers,
                    timeout=30,  # Match Gunicorn timeout
                )
                success = resp.status_code == 201
            except Exception:
                pass

            end_time = time.time()

            # Send result back with timing
            result_queue.put({"success": success, "duration": end_time - start_time})

        except Empty:
            continue


def monitor(result_queue, stop_event):  # NOSONAR
    """Monitor process that collects results and prints progress."""
    success = 0
    failed = 0
    completed = 0
    start_time = time.time()

    print(
        f"Creating {TOTAL_KEYS:,} API keys with permission {PERMISSION} "
        f"using {NUM_WORKERS} workers..."
    )
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    while not stop_event.is_set() or not result_queue.empty():
        try:
            result = result_queue.get(timeout=0.1)
            completed += 1

            if result["success"]:
                success += 1
            else:
                failed += 1

            # Print progress every 100 keys
            if completed % 100 == 0 or completed == TOTAL_KEYS:
                elapsed = time.time() - start_time
                keys_per_second = completed / elapsed if elapsed > 0 else 0
                remaining_keys = TOTAL_KEYS - completed
                eta_seconds = remaining_keys / keys_per_second if keys_per_second > 0 else 0

                print(
                    f"Progress: {completed:,}/{TOTAL_KEYS:,} ({completed/TOTAL_KEYS*100:.2f}%) | "
                    f"Success: {success:,} | Failed: {failed} | "
                    f"Speed: {keys_per_second:.2f} keys/s | "
                    f"Runtime: {format_time(elapsed)} | "
                    f"ETA: {format_time(eta_seconds)}",
                    end="\r",
                )

        except Empty:
            continue

    total_time = time.time() - start_time
    avg_speed = TOTAL_KEYS / total_time if total_time > 0 else 0

    print(f"\n\nComplete! Success: {success:,} | Failed: {failed:,}")
    print(f"Total Runtime: {format_time(total_time)}")
    print(f"Average Speed: {avg_speed:.2f} keys/second")
    print(f"Finished at: {time.strftime('%Y-%m-%d %H:%M:%S')}")


def main():
    task_queue = Queue(maxsize=NUM_WORKERS * 10)  # Limit queue size to prevent memory issues
    result_queue = Queue()
    stop_event = Event()

    # Start worker processes
    workers = []
    for i in range(NUM_WORKERS):
        p = Process(target=worker, args=(i, task_queue, result_queue, stop_event))
        p.start()
        workers.append(p)

    # Start monitor process
    monitor_process = Process(target=monitor, args=(result_queue, stop_event))
    monitor_process.start()

    # Feed tasks to the queue
    try:
        for i in range(TOTAL_KEYS):
            task_queue.put(i)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Stopping...")

    # Signal workers to stop
    stop_event.set()

    # Wait for workers to finish
    for p in workers:
        p.join()

    # Wait for monitor to finish
    monitor_process.join()


if __name__ == "__main__":
    main()
