#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Wrapper around the pdf signal type.
"""

import pathlib
import warnings
from io import StringIO

from threatexchange.signal_type import signal_base

TLSH_CONFIDENT_MATCH_THRESHOLD = 30
EXPECT_TLSH_HASH_LENGTH = 72

try:
    import tlsh
    from pdfminer.converter import TextConverter
    from pdfminer.layout import LAParams
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfparser import PDFParser

    _ENABLED = True
except ImportError:
    _ENABLED = False


class TLSHSignal(
    signal_base.SimpleSignalType, signal_base.TextHasher, signal_base.BytesHasher
):
    """
    Simple signal type for PDFs using TLSH

    Extracts the text from a given pdf using pdfminer.six and hashes it with TLSH

    """

    INDICATOR_TYPE = "HASH_TEXT_TLSH"

    @classmethod
    def hash_from_file(cls, path: pathlib.Path) -> str:
        # TODO - Move this into content type
        if not str(path).endswith(".pdf"):
            warnings.warn("File does not appear to be a pdf. ", category=UserWarning)
            return ""
        text = StringIO()
        with path.open("rb") as in_file:
            parser = PDFParser(in_file)
            doc = PDFDocument(parser)
            rsrcmgr = PDFResourceManager()
            device = TextConverter(rsrcmgr, text, laparams=LAParams())
            interpreter = PDFPageInterpreter(rsrcmgr, device)
            for page in PDFPage.create_pages(doc):
                interpreter.process_page(page)
        return cls.hash_from_bytes(text.getvalue().encode())

    @classmethod
    def hash_from_str(cls, text: str) -> str:
        return cls.hash_from_bytes(text.encode())

    @classmethod
    def hash_from_bytes(cls, bytes_: bytes) -> str:
        assert _ENABLED
        return str(tlsh.hash(bytes))

    @classmethod
    def compare_hash(cls, hash1: str, hash2: str) -> signal_base.HashComparisonResult:
        dist = tlsh.diffxlen(hash1, hash2)
        return signal_base.HashComparisonResult.from_dist(
            dist, TLSH_CONFIDENT_MATCH_THRESHOLD
        )
