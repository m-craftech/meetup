import base64
import gc
import json
import logging
from datetime import datetime, timedelta
from stix2.v21 import (
    AttackPattern,
    Bundle,
    Identity,
    ObservedData,
    IPv4Address,
    Relationship,
    NetworkTraffic,
    DomainName,
    HTTPRequestExt,
    CustomObservable,
    ExternalReference,
)
from stix2 import properties as stix2_properties
from uuid import uuid5, uuid4, NAMESPACE_DNS
from urllib.parse import urlparse
from tqdm import tqdm

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


@CustomObservable(
    "x-action",
    [
        ("action", stix2_properties.StringProperty(required=True)),
    ],
)
class WafLogAction:
    pass


@CustomObservable(
    "x-uri",
    [
        ("uri", stix2_properties.StringProperty(required=True)),
    ],
)
class WafLogUri:
    pass


def generate_uuid4():
    return str(uuid4())


def generate_uuid5(value):
    return str(uuid5(NAMESPACE_DNS, value))


def generate_uuid_for_relationship(src_ip_id, target_id):
    return generate_uuid5(src_ip_id + target_id)


def convert_timestamp_to_iso(timestamp):
    dt = datetime.utcfromtimestamp(
        timestamp / 1000
    )  # Convert UNIX timestamp to datetime
    dt = dt.replace(
        microsecond=(timestamp % 1000) * 1000
    )  # Add milliseconds to datetime
    return (
        dt.isoformat() + "Z"
    )  # Convert datetime to ISO 8601 (format expected by STIX)


current_timestamp = int(datetime.now().timestamp() * 1000)


ref_capec = ExternalReference(
    source_name="capec",
    url="https://capec.mitre.org/data/definitions/488.html",
    external_id="CAPEC-488",
)

attack_pattern = AttackPattern(
    type="attack-pattern",
    spec_version="2.1",
    id="attack-pattern--f6050ea6-a9a3-4524-93ed-c27858d6cb3c",
    name="HTTP Flood",
    external_references=[ref_capec],
    created=convert_timestamp_to_iso(current_timestamp),
    modified=convert_timestamp_to_iso(current_timestamp),
)


def map_log_to_stix(waf_log, identity):
    try:
        action = WafLogAction(action=waf_log["action"])
        uri = urlparse(waf_log["httpRequest"]["uri"].strip())
        http_request = waf_log["httpRequest"]
        number_observed = 1
        first_observed_timestamp = datetime.utcfromtimestamp(
            waf_log["timestamp"] / 1000
        )
        last_observed_timestamp = first_observed_timestamp + timedelta(milliseconds=1)
        first_observed = convert_timestamp_to_iso(waf_log["timestamp"])
        last_observed = convert_timestamp_to_iso(
            int(last_observed_timestamp.timestamp() * 1000)
        )
        src_ip = IPv4Address(
            id="ipv4-addr--" + generate_uuid4(),
            value=http_request["clientIp"],
        )
        host_value = next(
            (
                header["value"]
                for header in http_request["headers"]
                if header["name"] == "Host"
            ),
            "unknown",
        )
        dst_domain = DomainName(
            id="domain-name--" + generate_uuid5(host_value),
            value=host_value,
        )
        protocol = (
            "https"
            if any(
                header["name"] == "X-Forwarded-Proto" and header["value"] == "https"
                for header in http_request["headers"]
            )
            else "http"
        )
        src_port = int(
            next(
                (
                    header["value"]
                    for header in http_request["headers"]
                    if header["name"] == "X-Forwarded-Port"
                ),
                "0",
            )
        )
        dst_port = 443 if protocol == "https" else 80

        http_request_ext = HTTPRequestExt(
            request_method=waf_log["httpRequest"]["httpMethod"],
            request_value=uri.path,
            request_version=waf_log["httpRequest"]["httpVersion"],
            request_header={
                "X-Forwarded-For": next(
                    (
                        header["value"]
                        for header in http_request["headers"]
                        if header["name"] == "X-Forwarded-For"
                    ),
                    "N/A",
                ),
                "User-Agent": next(
                    (
                        header["value"]
                        for header in http_request["headers"]
                        if header["name"] == "User-Agent"
                    ),
                    "N/A",
                ),
            },
        )
        network_traffic = NetworkTraffic(
            id="network-traffic--" + generate_uuid5(src_ip.value + dst_domain.value),
            start=first_observed,
            end=last_observed,
            is_active=False,
            src_ref=src_ip.id,
            dst_ref=dst_domain.id,
            src_port=src_port,
            dst_port=dst_port,
            protocols=[protocol],
            extensions={"http-request-ext": http_request_ext},
        )
        observed_data = ObservedData(
            id="observed-data--" + generate_uuid5(network_traffic.id),
            first_observed=first_observed,
            last_observed=last_observed,
            number_observed=number_observed,
            created_by_ref=identity.id,
            objects={
                "0": network_traffic,
                "1": src_ip,
                "2": dst_domain,
                "3": action,
                "4": WafLogUri(uri=uri.path),
            },
        )

        return observed_data

    except Exception as e:
        logger.error(f"Error processing log to STIX: {e}", exc_info=True)
        return None


def process_record(record, identity):
    encoded_data = record["kinesis"]["data"]
    decoded_data = base64.b64decode(encoded_data).decode()
    waf_log = json.loads(decoded_data)
    observed_data = map_log_to_stix(waf_log, identity)

    if observed_data:
        relationship = Relationship(
            id="relationship--" + generate_uuid4(),
            relationship_type="related-to",
            source_ref=observed_data.id,
            target_ref=attack_pattern.id,
            created=convert_timestamp_to_iso(current_timestamp),
            modified=convert_timestamp_to_iso(current_timestamp),
        )
        yield observed_data
        yield relationship


def handler(event, context):
    try:
        identity = Identity(
            id="identity--" + generate_uuid4(),
            name="AWS WAF",
            identity_class="system",
            created=convert_timestamp_to_iso(current_timestamp),
            modified=convert_timestamp_to_iso(current_timestamp),
        )

        stix_objects = []

        for record in tqdm(event["Records"], desc="Processing records"):
            for obj in process_record(record, identity):
                stix_objects.append(obj)

        gc.collect()
        bundle = Bundle(attack_pattern, identity, *stix_objects, allow_custom=True)
        serialized_bundle = bundle.serialize(sort_keys=True, indent=4)

        bundle_dict = json.loads(serialized_bundle)

        for obj in bundle_dict["objects"]:
            if "spec_version" in obj:
                del obj["spec_version"]

        return json.dumps(bundle_dict, indent=4)

    except Exception as e:
        logger.error(f"Error processing event: {e}", exc_info=True)
        return None
