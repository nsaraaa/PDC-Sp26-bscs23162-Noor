import threading
import os

import httpx


BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")


def reset_document():
    httpx.post(f"{BASE_URL}/docs/1/reset", json={"content": "Original text"}, timeout=5)


def show_header():
    response = httpx.get(f"{BASE_URL}/health", timeout=5)
    print(f"Required header: X-Student-ID: {response.headers.get('X-Student-ID')}")


def run_naive_lost_update_demo():
    print("\n=== BEFORE: naive last-write-wins update ===")
    reset_document()
    barrier = threading.Barrier(2)

    def edit_document(user_label):
        document = httpx.get(f"{BASE_URL}/docs/1", timeout=5).json()
        barrier.wait()
        new_content = f"{document['content']} + {user_label}"
        response = httpx.put(
            f"{BASE_URL}/naive/docs/1",
            json={"content": new_content},
            timeout=5,
        )
        print(f"{user_label} saved HTTP {response.status_code}: {new_content}")

    threads = [
        threading.Thread(target=edit_document, args=("User A changes",)),
        threading.Thread(target=edit_document, args=("User B changes",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    final_document = httpx.get(f"{BASE_URL}/docs/1", timeout=5).json()
    print(f"Final document: {final_document}")
    # print("Result: one user's edit was silently overwritten.")


def run_optimistic_locking_demo():
    print("\n=== AFTER: optimistic locking update ===")
    reset_document()
    barrier = threading.Barrier(2)

    def edit_document(user_label):
        document = httpx.get(f"{BASE_URL}/docs/1", timeout=5).json()
        barrier.wait()
        new_content = f"{document['content']} + {user_label}"
        response = httpx.put(
            f"{BASE_URL}/docs/1",
            json={"content": new_content, "version": document["version"]},
            timeout=5,
        )
        print(f"{user_label} saved HTTP {response.status_code}: {response.json()}")

    threads = [
        threading.Thread(target=edit_document, args=("User A changes",)),
        threading.Thread(target=edit_document, args=("User B changes",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    final_document = httpx.get(f"{BASE_URL}/docs/1", timeout=5).json()
    print(f"Final document: {final_document}")
    # print("Result: stale writes are rejected with HTTP 409 instead of overwriting data.")


if __name__ == "__main__":
    show_header()
    run_naive_lost_update_demo()
    run_optimistic_locking_demo()
