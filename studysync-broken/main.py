from threading import Lock
from typing import Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


STUDENT_ID = "BSCS23162"

app = FastAPI(title="StudySync Resilient Backend")


class DocumentUpdate(BaseModel):
    content: str = Field(min_length=1)
    version: int = Field(ge=1)


class NaiveDocumentUpdate(BaseModel):
    content: str = Field(min_length=1)


class ResetDocument(BaseModel):
    content: str = "Original text"


documents: Dict[str, dict] = {
    "1": {"id": "1", "content": "Original text", "version": 1}
}
document_lock = Lock()


@app.middleware("http")
async def add_student_id_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Student-ID"] = STUDENT_ID
    return response


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/docs/{doc_id}/reset")
def reset_document(doc_id: str, payload: ResetDocument):
    with document_lock:
        documents[doc_id] = {"id": doc_id, "content": payload.content, "version": 1}
        return documents[doc_id]


@app.get("/docs/{doc_id}")
def get_document(doc_id: str):
    with document_lock:
        document = documents.get(doc_id)
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")
        return dict(document)


@app.put("/naive/docs/{doc_id}")
def naive_update_document(doc_id: str, payload: NaiveDocumentUpdate):
    with document_lock:
        current = documents.get(doc_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Document not found")

        current["content"] = payload.content
        current["version"] += 1
        return dict(current)


@app.put("/docs/{doc_id}")
def update_document(doc_id: str, payload: DocumentUpdate):
    """Optimistic locking: clients must update the version they last read."""
    with document_lock:
        current = documents.get(doc_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Document not found")

        if payload.version != current["version"]:
            return JSONResponse(
                status_code=409,
                content={
                    "detail": "Version conflict",
                    "message": "Document changed after this client read it. Fetch latest version and retry.",
                    "current": dict(current),
                },
            )

        current["content"] = payload.content
        current["version"] += 1
        return dict(current)
