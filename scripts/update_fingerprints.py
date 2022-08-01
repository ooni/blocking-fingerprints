import io
import re
import json
import ast
from dataclasses import field, asdict, dataclass
from typing import Any, Dict, Optional, List
import requests
import csv

CP_FINGERPRINTS_CP = "https://raw.githubusercontent.com/censoredplanet/censoredplanet-analysis/master/pipeline/metadata/data/blockpage_signatures.json"
CP_FALSE_POSITIVE_CP = "https://raw.githubusercontent.com/censoredplanet/censoredplanet-analysis/master/pipeline/metadata/data/false_positive_signatures.json"
CL_DNS = "https://raw.githubusercontent.com/citizenlab/filtering-annotations/master/data/v1/dns.csv"
CL_HTTP = "https://raw.githubusercontent.com/citizenlab/filtering-annotations/master/data/v1/http.csv"
OO_FINGERPRINTS = "https://raw.githubusercontent.com/ooni/pipeline/master/af/fastpath/fastpath/utils.py"

# Scope can be one of:
# "nat" national level blockpage
# "isp" ISP level blockpage
# "prod" text pattern related to a middlebox product
# "inst" text pattern related to a voluntary instition blockpage (school, office)
# "vbw" vague blocking word
# "fp" fingerprint for false positives

# OONI scopes are:
# blocking locality: global > country > isp > local

ooni_scope_to_cl = {
    "global": "vbw",
    "country": "nat",
    "isp": "isp",
    "local": "inst",
}

csv_header_fields = [
    "name",
    "location_found",
    "pattern_type",
    "pattern",
    "scope",
    "confidence_no_fp",
    "expected_countries",
    "source",
    "exp_url",
    "notes",
    "other_names"
]

@dataclass
class Fingerprint:
    name: str
    pattern: str
    pattern_type: str
    location_found: str
    exp_url: Optional[str] = ""
    confidence_no_fp: Optional[int] = 5
    source: List[Optional[str]] = field(default_factory=list)
    scope: Optional[str] = ""
    notes: Optional[str] = ""
    expected_countries: Optional[List[str]] = field(default_factory=list)
    other_names: Optional[List[str]] = field(default_factory=list)

def load_ooni_fp_utils():
    resp = requests.get(OO_FINGERPRINTS)
    fingerprints_block = []
    open_curly_brakets = 0
    in_fingerprints_block = False
    # This assumes the curly bracket is on the same line as the string saying
    # "fingerprints = " otherwise it will break.
    for line in resp.text.split("\n"):
        if line.startswith("fingerprints"):
            in_fingerprints_block = True
            line = line.lstrip("fingerprints =").strip()

        if "{" in line:
            open_curly_brakets += 1
        if "}" in line:
            open_curly_brakets -= 1

        if in_fingerprints_block:
            fingerprints_block.append(line)

        if in_fingerprints_block and open_curly_brakets == 0:
            break
    return ast.literal_eval("\n".join(fingerprints_block))

def cp_pattern_type(pattern : str, default_pattern : str) -> str:
    if ".*" in pattern:
        return "regexp"
    return default_pattern

_regexp_escape_replacements = [
    "(", ")", "[", "]", "{", "}", "?", "*", "+", "-", "|", "^", "$", "\\", ".", "#", " ", "\t", "\n", "\r", "\v", "\f", "'", '"'
]
def unescape_regexp(regexp_str: str) -> str:
    r = regexp_str
    for c in _regexp_escape_replacements:
        r = r.replace("\\" + c, c)
    return r

def find_fingerprint(fingerprint_list : List[Fingerprint], fingerprint : Fingerprint) -> (int, Optional[Fingerprint]):
    for idx, fp in enumerate(fingerprint_list):
        if fp.location_found == fingerprint.location_found and fingerprint.pattern_type == fingerprint.pattern_type and fp.pattern == fingerprint.pattern:
            return idx, fp
    return 0, None

def fp_to_dict(fp: Fingerprint) -> Dict[str, Any]:
    d = asdict(fp)
    d["source"] = ",".join(d["source"])
    d["expected_countries"] = ",".join(d["expected_countries"])
    d["other_names"] = ",".join(d["other_names"])
    return d

def csv_row_to_fp(row):
    return Fingerprint(
        name=row["name"],
        pattern=row["pattern"],
        pattern_type=row["pattern_type"],
        location_found=row["location_found"],
        confidence_no_fp=int(row["confidence_no_fp"]),
        source=row["source"].split(","),
        scope=row["scope"],
        exp_url=row["exp_url"],
        notes=row["notes"],
        expected_countries=row["expected_countries"].split(","),
        other_names=row["other_names"].split(","),
    )

def load_existing_fps():
    fingerprints = []
    with open("fingerprints_http.csv", "r", encoding="utf-8") as in_file:
        reader = csv.DictReader(in_file)
        for row in reader:
            fingerprints.append(csv_row_to_fp(row))

    with open("fingerprints_dns.csv", "r", encoding="utf-8") as in_file:
        reader = csv.DictReader(in_file)
        for row in reader:
            fingerprints.append(csv_row_to_fp(row))
    return fingerprints

def main():
    fingerprints = load_existing_fps()

    def maybe_add_fingerprint(fp: Fingerprint) -> None:
        idx, found_fp = find_fingerprint(fingerprints, fp)
        if found_fp:
            if found_fp.scope == "" and fp.scope != "":
                found_fp.scope = fp.scope
            if found_fp.exp_url == "" and fp.exp_url != "":
                found_fp.exp_url = fp.exp_url
            if found_fp.name != fp.name and fp.name not in found_fp.other_names:
                found_fp.other_names.append(fp.name)
                found_fp.other_names = sorted(found_fp.other_names)
            if found_fp.notes == "" and fp.notes != "":
                found_fp.notes = fp.notes
            if fp.expected_countries:
                found_fp.expected_countries = sorted(list(set(found_fp.expected_countries).union(set(fp.expected_countries))))
            print(f"Found existing fp {found_fp} -- {fp}")
            fingerprints[idx] = found_fp
        else:
            print(f"Adding new FP {fp}")
            fingerprints.append(fp)

    def load_cp_fingeprints(url: str, fp_prefix: str, scope=""):
        resp = requests.get(url)
        for line in resp.text.split("\n"):
            if line == "":
                continue
            d = json.loads(line)
            pattern = d["pattern"]
            pattern_type = "contains"

            # So far the only regexp feature used is ".*", so we use this to
            # detect regular expressions in their fingerprintdb
            if ".*" not in pattern:
                pattern = unescape_regexp(pattern)
            else:
                pattern_type = "regexp"

            fp_name = fp_prefix + d["fingerprint"]
            if pattern.startswith("http://") or pattern.startswith("https://"):
                maybe_add_fingerprint(
                    Fingerprint(
                        name=fp_name + "_body",
                        source=["censored planet"],
                        location_found="body",
                        pattern=pattern,
                        pattern_type="contains",
                        scope=scope,
                    )
                )
                maybe_add_fingerprint(
                    Fingerprint(
                        name=fp_name + "_location",
                        source=["censored planet"],
                        location_found="header.location",
                        pattern=pattern,
                        pattern_type="prefix",
                        scope=scope,
                    )
                )
                continue

            if pattern.startswith("Location: "):
                maybe_add_fingerprint(
                    Fingerprint(
                        name=fp_name,
                        source=["censored planet"],
                        location_found="header.location",
                        pattern=pattern.lstrip("Location: "),
                        pattern_type="prefix",
                        scope=scope,
                    )
                )
                continue

            if pattern.startswith("Server: "):
                maybe_add_fingerprint(
                    Fingerprint(
                        name=fp_name,
                        source=["censored planet"],
                        location_found="header.location",
                        pattern=pattern.lstrip("Server: "),
                        pattern_type="prefix",
                        scope=scope,
                    )
                )
                continue

            maybe_add_fingerprint(
                Fingerprint(
                    name=fp_name,
                    source=["censored planet"],
                    location_found="body",
                    pattern=pattern,
                    pattern_type=pattern_type,
                    scope=scope,
                )
            )

    ooni_fingerprint = load_ooni_fp_utils()
    for cc, fingerprint_list in ooni_fingerprint.items():
        for idx, fp in enumerate(fingerprint_list):
            fp_name = f"ooni.{cc.lower()}_{idx}"
            location_found = ""
            if "body_match" in fp:
                location_found = "body"
                pattern = fp["body_match"]
                pattern_type = "contains"
            elif "header_name" in fp:
                header_name = fp["header_name"].lower()
                location_found = f"header.{header_name}"
                if "header_prefix" in fp:
                    pattern = fp["header_prefix"]
                    pattern_type = "prefix"
                elif "header_full" in fp:
                    pattern = fp["header_full"]
                    pattern_type = "full"
                else:
                    raise Exception("Unknown header position")
            elif "dns_full" in fp:
                pattern = fp["dns_full"]
                location_found = "dns"
                pattern_type = "full"
            else:
                raise Exception("Unsupported fingerprint")

            maybe_add_fingerprint(
                Fingerprint(
                    location_found=location_found,
                    name=fp_name,
                    pattern=pattern,
                    pattern_type=pattern_type,
                    confidence_no_fp=5,
                    exp_url="",
                    source=["ooni"],
                    scope=ooni_scope_to_cl.get(fp["locality"]),
                    expected_countries=[cc],
                    notes="",
                )
            )

    print(f"Fetching CL fingerprints from {CL_HTTP}")
    resp = requests.get(CL_HTTP)
    assert resp.status_code == 200
    csv_reader = csv.DictReader(io.StringIO(resp.text))
    for row in csv_reader:
        location_found = row["location_found"]
        pattern = row["pattern"]
        pattern_type = "contains"
        if location_found == "header":
            if pattern.startswith("Server: "):
                pattern = pattern.lstrip("Server: ")
                pattern_type = "prefix"
                location_found = "header.server"
            elif pattern.startswith("Location: "):
                pattern = pattern.lstrip("Location: ")
                pattern_type = "prefix"
                location_found = "header.location"

        fp = Fingerprint(
            name="cl." + row["name"],
            location_found=location_found,
            pattern=pattern,
            pattern_type=pattern_type,
            confidence_no_fp=row["confidence_no_fp"],
            exp_url=row["exp_url"],
            source=sorted(ast.literal_eval(row["source"])),
            scope=row["scope"],
            expected_countries=sorted(ast.literal_eval(row["expected_countries"])),
            notes=row["notes"],
        )
        if fp.location_found == "header":
            fp.location_found = "header.location"
        maybe_add_fingerprint(fp)

    print(f"Fetching CL fingerprints from {CL_DNS}")
    resp = requests.get(CL_DNS)
    assert resp.status_code == 200
    csv_reader = csv.DictReader(io.StringIO(resp.text))
    for row in csv_reader:
        fp = Fingerprint(
            name="cl." + row["name"],
            location_found="dns",
            pattern=row["response"],
            pattern_type="full",
            confidence_no_fp=row["confidence_no_fp"],
            exp_url=row["exp_url"],
            source=sorted(ast.literal_eval(row["source"])),
            scope=row["scope"],
            expected_countries=sorted(ast.literal_eval(row["expected_countries"])),
            notes=row["notes"],
        )
        maybe_add_fingerprint(fp)

    print(f"Fetching CP fingerprints from {CP_FINGERPRINTS_CP}")
    load_cp_fingeprints(url=CP_FINGERPRINTS_CP, fp_prefix="cp.")
    print(f"Fetching CP false positicve fingerprints from {CP_FALSE_POSITIVE_CP}")
    load_cp_fingeprints(url=CP_FALSE_POSITIVE_CP, fp_prefix="cp.fp_", scope="fp")

    fingerprint_names = set()
    for fp in fingerprints:
        if fp.name in fingerprint_names:
            print(f"Duplicate fingeprint with ID {fp.name}")
        fingerprint_names.add(fp.name)

    with open("fingerprints_http.csv", "w", newline="", encoding="utf-8") as out_file:
        writer = csv.DictWriter(out_file, fieldnames=csv_header_fields)
        writer.writeheader()
        writer.writerows(
            map(
                fp_to_dict,
                filter(lambda fp: fp.location_found != "dns", fingerprints),
            )
        )

    with open("fingerprints_dns.csv", "w", newline="", encoding="utf-8") as out_file:
        writer = csv.DictWriter(out_file, fieldnames=csv_header_fields)
        writer.writeheader()
        writer.writerows(
            map(
                fp_to_dict,
                filter(lambda fp: fp.location_found == "dns", fingerprints),
            )
        )

if __name__ == "__main__":
    main()
