# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

from hmalib.common.models.models_base import DynamoDBCursorKey
from urllib import parse
from datetime import datetime
import json
import uuid
import bottle
import typing as t
from dataclasses import asdict, dataclass, field
from urllib.parse import quote as uriencode

from mypy_boto3_dynamodb.service_resource import Table

from threatexchange.content_type.meta import get_content_type_for_name
from threatexchange.content_type.photo import PhotoContent
from threatexchange.content_type.video import VideoContent

from hmalib.common.models.bank import Bank, BankMember, BanksTable
from hmalib.banks import bank_operations as bank_ops
from hmalib.lambdas.api.middleware import jsoninator, JSONifiable
from hmalib.lambdas.api.submit import create_presigned_put_url, create_presigned_url


@dataclass
class AllBanksEnvelope(JSONifiable):
    banks: t.List[Bank]

    def to_json(self) -> t.Dict:
        return {"banks": [bank.to_json() for bank in self.banks]}


@dataclass
class PreviewableBankMember(BankMember):
    """
    A bank-member, but has a preview_url. preview_url should be pre-authorized,
    and of the same content_type as the original media.
    """

    preview_url: str = field(default_factory=lambda: "")


@dataclass
class BankMembersPage(JSONifiable):
    bank_members: t.List[PreviewableBankMember]

    # deserializes to dynamo's exclusive_start_key. Is a dict
    continuation_token: t.Optional[str]

    def to_json(self) -> t.Dict:
        result = asdict(self)
        result.update(bank_members=[member.to_json() for member in self.bank_members])
        return result


def with_preview_url(bank_member: BankMember) -> PreviewableBankMember:
    previewable = PreviewableBankMember(**asdict(bank_member))

    if bank_member.storage_bucket is None:
        return previewable

    previewable.preview_url = create_presigned_url(
        bucket_name=bank_member.storage_bucket,
        key=bank_member.storage_key,
        file_type=None,
        expiration=300,
        client_method="get_object",
    )
    return previewable


def with_preview_urls(
    bank_members: t.List[BankMember],
) -> t.List[PreviewableBankMember]:
    """
    For a list of bank_members, converts the storage details into a publicly
    visible image for UI to work with.
    """
    return list(map(with_preview_url, bank_members))


def get_bank_api(bank_table: Table, bank_user_media_bucket: str) -> bottle.Bottle:
    """
    Closure for dependencies of the bank API
    """

    bank_api = bottle.Bottle()
    table_manager = BanksTable(table=bank_table)

    # Bank Management

    @bank_api.get("/get-all-banks", apply=[jsoninator])
    def get_all_banks() -> AllBanksEnvelope:
        """
        Get all banks.
        """
        return AllBanksEnvelope(banks=table_manager.get_all_banks())

    @bank_api.get("/get-bank/<bank_id>", apply=[jsoninator])
    def get_bank(bank_id=None) -> Bank:
        """
        Get a specific bank from a bank_id.
        """
        bank = table_manager.get_bank(bank_id=bank_id)
        return bank

    @bank_api.post("/create-bank", apply=[jsoninator])
    def create_bank() -> Bank:
        """
        Create a bank using only the name and description.
        """
        return table_manager.create_bank(
            bank_name=bottle.request.json["bank_name"],
            bank_description=bottle.request.json["bank_description"],
        )

    @bank_api.post("/update-bank/<bank_id>", apply=[jsoninator])
    def update_bank(bank_id=None) -> Bank:
        """
        Update name and description for a bank_id.
        """
        return table_manager.update_bank(
            bank_id=bank_id,
            bank_name=bottle.request.json["bank_name"],
            bank_description=bottle.request.json["bank_description"],
        )

    # Member Management

    @bank_api.get("/get-members/<bank_id>", apply=[jsoninator])
    def get_members(bank_id=None) -> BankMembersPage:
        """
        Get a page of bank members. Use the "continuation_token" from this
        response to get subsequent pages.
        """
        continuation_token = (
            bottle.request.query.continuation_token
            and json.loads(bottle.request.query.continuation_token)
            or None
        )

        try:
            content_type = get_content_type_for_name(bottle.request.query.content_type)

        except:
            bottle.abort(400, "content_type must be provided as a query parameter.")

        db_response = table_manager.get_all_bank_members_page(
            bank_id=bank_id,
            content_type=content_type,
            exclusive_start_key=continuation_token,
        )

        continuation_token = None
        if db_response.last_evaluated_key:
            continuation_token = uriencode(json.dumps(db_response.last_evaluated_key))

        return BankMembersPage(
            bank_members=with_preview_urls(db_response.items),
            continuation_token=continuation_token,
        )

    @bank_api.post("/add-member/<bank_id>", apply=[jsoninator])
    def add_member(bank_id=None) -> PreviewableBankMember:
        """
        Add a bank member. Expects a JSON object with following fields:
        - content_type: ["photo"|"video"]
        - storage_bucket: s3bucket for the media
        - storage_key: key for the media on s3
        - notes: String, any additional notes you want to associate with this
            member.

        Clients would want to use get_media_upload_url() to get a
        storage_bucket, storage_key and a upload_url before using add_member()

        Returns 200 OK with the resulting bank_member. 500 on failure.
        """
        content_type = get_content_type_for_name(bottle.request.json["content_type"])
        storage_bucket = bottle.request.json["storage_bucket"]
        storage_key = bottle.request.json["storage_key"]
        notes = bottle.request.json["notes"]

        return with_preview_url(
            bank_ops.add_bank_member(
                banks_table=table_manager,
                bank_id=bank_id,
                content_type=content_type,
                storage_bucket=storage_bucket,
                storage_key=storage_key,
                raw_content=None,
                notes=notes,
            )
        )

    # Miscellaneous
    @bank_api.post("/get-media-upload-url")
    def get_media_upload_url(media_type=None):
        """
        Get a presigned S3 url that can be used by the client to PUT an object.

        Request Payload must be json with the following attributes:

        `media_type` must be something like ['image/gif', 'image/png', 'application/zip']
        `extension` must be a period followed by file extension. eg. `.mp4`, `.jpg`
        """
        extension = bottle.request.json.get("extension")
        media_type = bottle.request.json.get("media_type")

        if (not extension) or extension[0] != ".":
            bottle.abort(400, "extension must start with a period. eg. '.mp4'")

        id = str(uuid.uuid4())
        today_fragment = datetime.now().isoformat("|").split("|")[0]  # eg. 2019-09-12
        s3_key = f"bank-media/{media_type}/{today_fragment}/{id}{extension}"

        return {
            "storage_bucket": bank_user_media_bucket,
            "storage_key": s3_key,
            "upload_url": create_presigned_put_url(
                bucket_name=bank_user_media_bucket,
                key=s3_key,
                file_type=media_type,
                expiration=3600,
            ),
        }

    return bank_api
