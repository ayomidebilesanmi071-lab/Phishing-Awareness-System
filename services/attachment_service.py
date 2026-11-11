"""Attachment (evidence file) handling.

Uploaded evidence is treated as untrusted input:

* only a small allow-list of extensions is accepted,
* files are renamed to a random UUID so original names can never collide
  or be used for path traversal,
* the original display name is sanitized with ``secure_filename``,
* files are served with ``Content-Disposition: attachment`` so the browser
  downloads rather than renders them.
"""

import os
import uuid

from flask import current_app
from werkzeug.utils import secure_filename


class AttachmentError(ValueError):
    """Raised when an uploaded file is rejected."""


class AttachmentService:
    """Stores evidence uploads safely and resolves them for download."""

    @staticmethod
    def save(file_storage):
        """Save an uploaded file and return (stored_name, original_name).

        Returns ``(None, None)`` when no file was provided.
        """
        if file_storage is None or not file_storage.filename:
            return None, None

        original = file_storage.filename
        ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
        allowed = current_app.config["ALLOWED_ATTACHMENT_EXTENSIONS"]
        if ext not in allowed:
            raise AttachmentError(
                "File type "
                f"'.{ext or 'unknown'}' is not allowed. Allowed types: "
                f"{', '.join(sorted(allowed))}."
            )

        stored_name = f"{uuid.uuid4().hex}.{ext}"
        folder = current_app.config["UPLOAD_FOLDER"]
        file_storage.save(os.path.join(folder, stored_name))
        return stored_name, secure_filename(original) or original

    @staticmethod
    def resolve_path(stored_name):
        """Return the absolute path of a stored attachment.

        Guards against path traversal: the resolved path must stay inside
        the uploads folder, and the file must exist.
        """
        folder = os.path.abspath(current_app.config["UPLOAD_FOLDER"])
        full = os.path.abspath(os.path.join(folder, stored_name or ""))
        if os.path.commonpath([folder, full]) != folder or not os.path.isfile(full):
            raise FileNotFoundError("Attachment not found.")
        return full
