import sys
import base64
from struct import unpack
import argparse
from uuid import UUID
import datetime

SKIP_ATTR_CLEAN = {
    "objectsid",
    "objectguid",
    "ntsecuritydescriptor",
    "msds-generationid",
    "auditingpolicy",
    "dsasignature",
    "ms-ds-creatorsid",
    "logonhours",
    "schemaidguid",
    "msexchmailboxsecuritydescriptor",
    "msexchmailboxguid",
    "thumbnailphoto",
}

DATE_ATTRS = {
    "pwdlastset",
    "accountexpires",
    "lastlogon",
    "lastlogontimestamp",
    "lastpwdset",
    "badpasswordtime",
}

UAC_FLAGS = (
    ("SCRIPT", 0x0001),
    ("ACCOUNTDISABLE", 0x0002),
    ("HOMEDIR_REQUIRED", 0x0008),
    ("LOCKOUT", 0x0010),
    ("PASSWD_NOTREQD", 0x0020),
    ("PASSWD_CANT_CHANGE", 0x0040),
    ("ENCRYPTED_TEXT_PWD_ALLOWED", 0x0080),
    ("TEMP_DUPLICATE_ACCOUNT", 0x0100),
    ("NORMAL_ACCOUNT", 0x0200),
    ("INTERDOMAIN_TRUST_ACCOUNT", 0x0800),
    ("WORKSTATION_TRUST_ACCOUNT", 0x1000),
    ("SERVER_TRUST_ACCOUNT", 0x2000),
    ("DONT_EXPIRE_PASSWORD", 0x10000),
    ("MNS_LOGON_ACCOUNT", 0x20000),
    ("SMARTCARD_REQUIRED", 0x40000),
    ("TRUSTED_FOR_DELEGATION", 0x80000),
    ("NOT_DELEGATED", 0x100000),
    ("USE_DES_KEY_ONLY", 0x200000),
    ("DONT_REQ_PREAUTH", 0x400000),
    ("PASSWORD_EXPIRED", 0x800000),
    ("TRUSTED_TO_AUTH_FOR_DELEGATION", 0x1000000),
    ("PARTIAL_SECRETS_ACCOUNT", 0x04000000),
)


SID_FIELD = {"objectsid"}


def main(mode):
    parser = PARSERS[mode]

    if mode == "bof":
        _separator = "--------------------\n"
        sys.stdout.write(_separator)

    for line in sys.stdin:
        parser(line)


def format_unicode(raw_value):
    try:
        if str is not bytes:  # Python 3
            return str(raw_value, "utf-8", errors="strict")
        else:  # Python 2
            return unicode(raw_value, "utf-8", errors="strict")
    except (TypeError, UnicodeDecodeError):
        pass

    return raw_value


def format_uuid_le(raw_value):
    try:
        return "{" + str(UUID(bytes_le=raw_value)) + "}"
    except (TypeError, ValueError):
        return format_unicode(raw_value)
    except (
        Exception
    ):  # any other exception should be investigated, anyway the formatter return the raw_value
        pass

    return raw_value


def clean_binary_value(value):
    try:
        return True, base64.b64decode(value).decode("UTF-8").replace("\n", "\n ")
    except UnicodeDecodeError:
        return False, value


def parse_sid(value):
    data = base64.b64decode(value)
    version, _, _, authority = unpack(">BchI", data[0:8])
    domain1, domain2, domain3, domain4, relative_id = unpack("<IIIII", data[8:])
    return (
        f"S-{version}-{authority}-{domain1}-{domain2}-{domain3}-{domain4}-{relative_id}"
    )


def parse_ad_timestamp(timestamp_str):
    try:
        timestamp = int(timestamp_str)
        if timestamp != 0:
            return (datetime.datetime(1601, 1, 1) + datetime.timedelta(
                seconds=timestamp / 10000000
            )).isoformat()
        return timestamp_str
    except:
        return timestamp_str


def transform_useraccountcontrol(uac: str) -> str:
    uac = int(uac)
    flags = []
    for flag_name, flag in UAC_FLAGS:
        if uac & flag:
            flags.append(flag_name)

    return "|".join(flags)


def clean_parser(line):
    line = line.strip()
    if line.startswith("#") or not line:
        sys.stdout.write(line)
    else:
        attr, value = line.split(":", 1)
        # value = value.strip()
        if value.startswith(":") and attr.lower() not in SKIP_ATTR_CLEAN:
            processed, cleaned_value = clean_binary_value(value)
            if processed:
                sys.stdout.write(": ".join((attr, cleaned_value)))
            else:
                sys.stdout.write(":: ".join((attr, value)))

        elif value.startswith(":") and attr.lower() in SID_FIELD:
            sys.stdout.write(": ".join((attr, parse_sid(value))))
        elif attr.lower() in DATE_ATTRS:
            sys.stdout.write(": ".join((attr, parse_ad_timestamp(value))))
        elif attr.lower() == "useraccountcontrol":
            sys.stdout.write(": ".join((attr, transform_useraccountcontrol(value))))
        else:
            sys.stdout.write(":".join((attr, value)))

    sys.stdout.write("\n")
    sys.stdout.flush()


def raw_parser(line):
    sys.stdout.write(line)


def bof_parser(line):
    _separator = "--------------------\n"
    # bofhound expects some attributes in a certain format
    _base64_attributes = {
        "ntsecuritydescriptor",
        "msds-generationid",
        "auditingpolicy",
        "dsasignature",
        "ms-ds-creatorsid",
        "logonhours",
        "schemaidguid",
    }
    _raw_attributes = {
        "whencreated",
        "whenchanged",
        "dscorepropagationdata",
        "accountexpires",
        "badpasswordtime",
        "pwdlastset",
        "lastlogontimestamp",
        "lastlogon",
        "lastlogoff",
        "maxpwdage",
        "minpwdage",
        "creationtime",
        "lockoutobservationwindow",
        "lockoutduration",
    }
    _bracketed_attributes = {"objectguid"}
    _ignore_attributes = {"usercertificate"}

    if line == "\n":
        sys.stdout.write(_separator)
    else:
        try:
            attr, value = line.split(": ", 1)
        except:
            return

        is_base64 = attr.endswith(":")
        attr = str(attr).strip(":")

        if attr.lower() in _ignore_attributes:
            return

        if attr.lower() in _bracketed_attributes:
            value = format_uuid_le(base64.b64decode(value))

        if is_base64 and attr.lower() not in _base64_attributes:
            _, value = clean_binary_value(value)

        sys.stdout.write(f"{attr}: {value.strip()}\n")


PARSERS = {"raw": raw_parser, "clean": clean_parser, "bof": bof_parser}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=PARSERS.keys(), default="clean")
    ops = parser.parse_args()

    main(ops.mode)
