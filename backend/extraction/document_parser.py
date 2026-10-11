"""Secure Document Parsing and Text Extraction Module.

Supports:
- Plain Text (.txt, .md, .csv, .json)
- PDF Documents (.pdf via pypdf)
- Microsoft Word Documents (.docx via python-docx)

Security Guarantees:
- Path traversal immunity (sanitizes filenames via os.path.basename)
- File size bounds (rejects files > 10MB)
- Extracted content bounds (rejects or truncates content > 1MB)
- Magic byte validation to prevent MIME-type spoofing
- In-memory execution using BytesIO with zero disk persistence or file leakage
- Safe error handling without stack trace or credential exposure
"""

import io
import json
import logging
import os
import zipfile
from dataclasses import dataclass
from typing import Optional, Tuple

import pypdf
import docx

from backend.config import settings

logger = logging.getLogger("promptshield.extraction")

MAX_PDF_PAGES = 300


@dataclass
class DocumentExtractionResult:
    """Structured result of secure document parsing."""
    filename: str
    file_type: str
    file_size_bytes: int
    extracted_text: str
    extracted_chars: int
    page_count: Optional[int] = None


class SafeDocumentParser:
    """Secure, in-memory parser for uploaded document files."""

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Strip directory traversal sequences and unsafe characters from filenames."""
        if not filename:
            return "unnamed_document.txt"
        base = os.path.basename(filename)
        # Remove any non-standard characters
        safe_name = "".join(c for c in base if c.isalnum() or c in "._- ")
        return safe_name or "document.txt"

    @classmethod
    def validate_file(cls, filename: str, file_bytes: bytes) -> Tuple[bool, Optional[str], str]:
        """Validate filename extension, size, and magic bytes before parsing."""
        if not file_bytes or len(file_bytes) == 0:
            return False, "Uploaded file is completely empty (0 bytes).", ""

        max_size = settings.MAX_DOCUMENT_SIZE_BYTES
        if len(file_bytes) > max_size:
            return (
                False,
                f"File size ({len(file_bytes)} bytes) exceeds maximum permitted limit ({max_size} bytes).",
                "",
            )

        safe_name = cls.sanitize_filename(filename)
        ext = os.path.splitext(safe_name)[1].lower()

        if ext not in settings.ALLOWED_DOCUMENT_EXTENSIONS:
            allowed_list = ", ".join(sorted(settings.ALLOWED_DOCUMENT_EXTENSIONS))
            return (
                False,
                f"Unsupported file format '{ext}'. Supported formats: {allowed_list}.",
                "",
            )

        # Magic byte & structure verification
        if ext == ".pdf":
            if not file_bytes.startswith(b"%PDF-"):
                return False, "File extension is .pdf, but file content does not match a valid PDF header.", ext
        elif ext == ".docx":
            if not file_bytes.startswith(b"PK\x03\x04"):
                return False, "File extension is .docx, but file content does not match a valid Office Open XML ZIP header.", ext
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                    if "word/document.xml" not in zf.namelist():
                        return False, "Malformed DOCX archive: missing word/document.xml entry.", ext
            except Exception:
                return False, "Corrupted or invalid DOCX archive file.", ext
        else:
            # Plain text / markdown / csv / json: check for excessive binary null bytes
            null_count = file_bytes[:1024].count(b"\x00")
            if null_count > 5:
                return False, "File appears to contain executable binary data rather than plain text.", ext

        return True, None, ext

    @classmethod
    def extract_text(cls, filename: str, file_bytes: bytes) -> DocumentExtractionResult:
        """Extract text from supported document types safely in memory."""
        is_valid, error_msg, ext = cls.validate_file(filename, file_bytes)
        if not is_valid:
            raise ValueError(f"Document Validation Failed: {error_msg}")

        safe_name = cls.sanitize_filename(filename)
        extracted_text = ""
        page_count = None

        try:
            if ext == ".pdf":
                extracted_text, page_count = cls._extract_pdf(file_bytes)
            elif ext == ".docx":
                extracted_text = cls._extract_docx(file_bytes)
            elif ext == ".json":
                extracted_text = cls._extract_json(file_bytes)
            else:
                # Text, Markdown, CSV
                extracted_text = cls._extract_plain_text(file_bytes)
        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error parsing document '{safe_name}': {str(e)}", exc_info=True)
            raise ValueError(f"Failed to parse document content: {str(e)}")

        if not extracted_text or not extracted_text.strip():
            raise ValueError("Document contains no extractable text or is an empty/scanned document.")

        # Truncate text if it exceeds maximum content length
        if len(extracted_text) > settings.MAX_CONTENT_LENGTH:
            extracted_text = extracted_text[:settings.MAX_CONTENT_LENGTH]

        return DocumentExtractionResult(
            filename=safe_name,
            file_type=ext.lstrip("."),
            file_size_bytes=len(file_bytes),
            extracted_text=extracted_text,
            extracted_chars=len(extracted_text),
            page_count=page_count,
        )

    @staticmethod
    def _extract_plain_text(file_bytes: bytes) -> str:
        """Decode plain text files safely using UTF-8 with fallback."""
        try:
            return file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return file_bytes.decode("utf-16")
            except UnicodeDecodeError:
                return file_bytes.decode("latin-1", errors="replace")

    @staticmethod
    def _extract_json(file_bytes: bytes) -> str:
        """Parse JSON text and return formatted string representation."""
        text = file_bytes.decode("utf-8", errors="replace")
        try:
            data = json.loads(text)
            return json.dumps(data, indent=2)
        except Exception:
            return text

    @staticmethod
    def _extract_pdf(file_bytes: bytes) -> Tuple[str, int]:
        """Extract text from PDF pages using pypdf."""
        stream = io.BytesIO(file_bytes)
        try:
            reader = pypdf.PdfReader(stream)
            total_pages = len(reader.pages)

            if total_pages > MAX_PDF_PAGES:
                raise ValueError(
                    f"PDF page count ({total_pages}) exceeds maximum allowed limit ({MAX_PDF_PAGES} pages)."
                )

            extracted_chunks = []
            for page_num in range(total_pages):
                page = reader.pages[page_num]
                text = page.extract_text()
                if text:
                    extracted_chunks.append(text)

            combined_text = "\n\n".join(extracted_chunks)
            return combined_text, total_pages
        finally:
            stream.close()

    @staticmethod
    def _extract_docx(file_bytes: bytes) -> str:
        """Extract text from DOCX paragraphs and tables using python-docx."""
        stream = io.BytesIO(file_bytes)
        try:
            doc = docx.Document(stream)
            chunks = []

            for p in doc.paragraphs:
                if p.text and p.text.strip():
                    chunks.append(p.text.strip())

            for table in doc.tables:
                for row in table.rows:
                    row_texts = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                    if row_texts:
                        chunks.append(" | ".join(row_texts))

            return "\n\n".join(chunks)
        finally:
            stream.close()
