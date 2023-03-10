#!/usr/bin/env python3
"""
Validate CSV files
"""
from pathlib import Path
from typing import TypedDict
import csv
import sys

SCOPES = ("isp", "nat", "prod", "inst", "fp", "vbw", "injb", "prov")
CCS = set(
    [
        "AD",
        "AE",
        "AF",
        "AG",
        "AI",
        "AL",
        "AM",
        "AO",
        "AQ",
        "AR",
        "AS",
        "AT",
        "AU",
        "AW",
        "AX",
        "AZ",
        "BA",
        "BB",
        "BD",
        "BE",
        "BF",
        "BG",
        "BH",
        "BI",
        "BJ",
        "BL",
        "BM",
        "BN",
        "BO",
        "BQ",
        "BR",
        "BS",
        "BT",
        "BV",
        "BW",
        "BY",
        "BZ",
        "CA",
        "CC",
        "CD",
        "CF",
        "CG",
        "CH",
        "CI",
        "CK",
        "CL",
        "CM",
        "CN",
        "CO",
        "CR",
        "CU",
        "CV",
        "CW",
        "CX",
        "CY",
        "CZ",
        "DE",
        "DJ",
        "DK",
        "DM",
        "DO",
        "DZ",
        "EC",
        "EE",
        "EG",
        "EH",
        "ER",
        "ES",
        "ET",
        "FI",
        "FJ",
        "FK",
        "FM",
        "FO",
        "FR",
        "GA",
        "GB",
        "GD",
        "GE",
        "GF",
        "GG",
        "GH",
        "GI",
        "GL",
        "GM",
        "GN",
        "GP",
        "GQ",
        "GR",
        "GS",
        "GT",
        "GU",
        "GW",
        "GY",
        "HK",
        "HM",
        "HN",
        "HR",
        "HT",
        "HU",
        "ID",
        "IE",
        "IL",
        "IM",
        "IN",
        "IO",
        "IQ",
        "IR",
        "IS",
        "IT",
        "JE",
        "JM",
        "JO",
        "JP",
        "KE",
        "KG",
        "KH",
        "KI",
        "KM",
        "KN",
        "KP",
        "KR",
        "KW",
        "KY",
        "KZ",
        "LA",
        "LB",
        "LC",
        "LI",
        "LK",
        "LR",
        "LS",
        "LT",
        "LU",
        "LV",
        "LY",
        "MA",
        "MC",
        "MD",
        "ME",
        "MF",
        "MG",
        "MH",
        "MK",
        "ML",
        "MM",
        "MN",
        "MO",
        "MP",
        "MQ",
        "MR",
        "MS",
        "MT",
        "MU",
        "MV",
        "MW",
        "MX",
        "MY",
        "MZ",
        "NA",
        "NC",
        "NE",
        "NF",
        "NG",
        "NI",
        "NL",
        "NO",
        "NP",
        "NR",
        "NU",
        "NZ",
        "OM",
        "PA",
        "PE",
        "PF",
        "PG",
        "PH",
        "PK",
        "PL",
        "PM",
        "PN",
        "PR",
        "PS",
        "PT",
        "PW",
        "PY",
        "QA",
        "RE",
        "RO",
        "RS",
        "RU",
        "RW",
        "SA",
        "SB",
        "SC",
        "SD",
        "SE",
        "SG",
        "SH",
        "SI",
        "SJ",
        "SK",
        "SL",
        "SM",
        "SN",
        "SO",
        "SR",
        "SS",
        "ST",
        "SV",
        "SX",
        "SY",
        "SZ",
        "TC",
        "TD",
        "TF",
        "TG",
        "TH",
        "TJ",
        "TK",
        "TL",
        "TM",
        "TN",
        "TO",
        "TR",
        "TT",
        "TV",
        "TW",
        "TZ",
        "UA",
        "UG",
        "UM",
        "US",
        "UY",
        "UZ",
        "VA",
        "VC",
        "VE",
        "VG",
        "VI",
        "VN",
        "VU",
        "WF",
        "WS",
        "YE",
        "YT",
        "ZA",
        "ZM",
        "ZW",
    ]
)
CCS.add("ZZ")  # ZZ is allowed in expected_countries


class Fingerprint(TypedDict):
    name: str
    scope: str
    other_names: str
    location_found: str
    pattern_type: str
    pattern: str
    confidence_no_fp: int
    expected_countries: list


def validate_row(pos, row, header) -> None:
    assert len(row) == len(
        header
    ), f"""{pos} Inconsistent row count in {row}
        expected {len(header)} got {len(row)}"""

    r = Fingerprint(zip(header, row))
    try:
        assert r["scope"] in SCOPES, f"""Invalid scope '{r["scope"]}'"""
        assert r["pattern"], "Empty pattern"
        loc = r["location_found"]
        assert loc in ("body", "dns") or loc.startswith(
            "header."
        ), f"Invalid location '{loc}'"

        pt = r["pattern_type"]
        assert pt in (
            "full",
            "prefix",
            "contains",
            "regexp",
        ), f"Invalid pattern_type '{pt}'"

        ec = r["expected_countries"]
        assert ec == ec.strip(), "Spaces or newlines around expected_countries"
        if ec == "":
            ccs = []
        else:
            ccs = ec.split(",")
        assert "" not in ccs, f"Spurious commas in expected_countries {repr(ec)}"
        for cc in ccs:
            assert cc in CCS, f"Unexpected CC '{cc}'"

    except AssertionError as e:
        print(f"--- error in {pos} ---")
        print(e)
        print(f"---\n{r}\n---")
        print("=== Validation failed ===")
        sys.exit(1)
    return r["name"]


def validate_csv(csv_path: Path):
    fp_names = set()
    with csv_path.open() as in_file:
        reader = csv.reader(in_file)
        header = next(reader)
        for idx, row in enumerate(reader):
            pos = f"{csv_path}:{idx+1}"
            fp_name = validate_row(pos, row, header)
            assert fp_name not in fp_names, f"{pos} Duplicate fingerprint name {fp_name}"
            fp_names.add(fp_name)


def main():
    validate_csv(Path("fingerprints_dns.csv"))
    validate_csv(Path("fingerprints_http.csv"))
    print("Validation successful")


if __name__ == "__main__":
    main()
