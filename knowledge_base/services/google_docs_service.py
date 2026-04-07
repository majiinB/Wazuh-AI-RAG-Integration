"""
knowledge_base/services/google_docs_service.py

Fetches document content from Google Docs API using a Service Account.

Setup:
1. Go to Google Cloud Console → IAM → Service Accounts
2. Create a service account, download the JSON key
3. Share your Google Docs with the service account email
4. Set GOOGLE_SERVICE_ACCOUNT_FILE in .env

pip install google-api-python-client google-auth
"""

import logging
from django.conf import settings
from googleapiclient.discovery import build
from google.oauth2 import service_account

logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/documents.readonly"]


def _get_docs_service():
    """Build and return an authenticated Google Docs API client."""
    credentials = service_account.Credentials.from_service_account_file(
        settings.GOOGLE_SERVICE_ACCOUNT_FILE,
        scopes=SCOPES,
    )
    return build("docs", "v1", credentials=credentials)


def fetch_document(google_doc_id: str) -> dict:
    """
    Fetch a Google Doc by its ID.

    Returns:
        {
            "title": str,
            "content": str,   # full plain text
            "url": str,
        }

    The google_doc_id is the long string in the Google Docs URL:
    https://docs.google.com/document/d/<GOOGLE_DOC_ID>/edit
    """
    service = _get_docs_service()

    try:
        doc = service.documents().get(documentId=google_doc_id).execute()
        title = doc.get("title", "Untitled")
        content = _extract_text(doc)
        url = f"https://docs.google.com/document/d/{google_doc_id}/edit"

        logger.info(f"Fetched Google Doc: '{title}' ({len(content)} chars)")
        return {"title": title, "content": content, "url": url}

    except Exception as e:
        logger.error(f"Failed to fetch Google Doc {google_doc_id}: {e}")
        raise


def _extract_text(doc: dict) -> str:
    """
    Extract plain text from a Google Docs document object.
    Preserves paragraph structure with newlines.
    """
    text_parts = []
    body = doc.get("body", {})
    content = body.get("content", [])

    for element in content:
        paragraph = element.get("paragraph")
        if not paragraph:
            continue

        para_text = ""
        for part in paragraph.get("elements", []):
            text_run = part.get("textRun")
            if text_run:
                para_text += text_run.get("content", "")

        if para_text.strip():
            text_parts.append(para_text.strip())

    return "\n\n".join(text_parts)