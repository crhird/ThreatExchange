#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Wrapper around the pdf content type.
"""

from threatexchange.content_type.content_base import ContentType


class PDFContent(ContentType):
    """
    Content that represents text in Portable Document Format.

    Examples might be:
    * PDFs
    """
