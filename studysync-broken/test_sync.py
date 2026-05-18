import threading

from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def reset_document():
    client.post("/docs/1/reset", json={"content": "Original text"})


def test_every_response_has_student_id_header():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Student-ID"] == "BSCS23162"


def test_naive_endpoint_loses_one_concurrent_update():
    reset_document()
    barrier = threading.Barrier(2)

    def edit_document(user_label):
        document = client.get("/docs/1").json()
        barrier.wait()
        content = f"{document['content']} + {user_label}"
        return client.put("/naive/docs/1", json={"content": content})

    responses = []
    threads = [
        threading.Thread(target=lambda: responses.append(edit_document("User A changes"))),
        threading.Thread(target=lambda: responses.append(edit_document("User B changes"))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    final_document = client.get("/docs/1").json()

    assert len(responses) == 2
    assert all(response.status_code == 200 for response in responses)
    assert not (
        "User A changes" in final_document["content"]
        and "User B changes" in final_document["content"]
    )


def test_optimistic_locking_rejects_stale_concurrent_update():
    reset_document()
    barrier = threading.Barrier(2)

    def edit_document(user_label):
        document = client.get("/docs/1").json()
        barrier.wait()
        content = f"{document['content']} + {user_label}"
        return client.put(
            "/docs/1",
            json={"content": content, "version": document["version"]},
        )

    responses = []
    threads = [
        threading.Thread(target=lambda: responses.append(edit_document("User A changes"))),
        threading.Thread(target=lambda: responses.append(edit_document("User B changes"))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    status_codes = sorted(response.status_code for response in responses)
    final_document = client.get("/docs/1").json()

    assert status_codes == [200, 409]
    assert final_document["version"] == 2
    assert "Original text" in final_document["content"]
