import unittest
import json
import csv
import os
from update_fingerprints import unescape_regexp

class Test(unittest.TestCase):
    def test_fp_gen(self):
        with open("tests/test_fp_cp.json") as in_file:
            lines = in_file.readlines()

        j = json.loads(lines[0])
        unescaped_pattern = unescape_regexp(j["pattern"])
        assert unescaped_pattern == 'src="http://www.ferra.ru/images/416/416695.jpeg"'

        j = json.loads(lines[3])
        unescaped_pattern = unescape_regexp(j["pattern"])
        assert unescaped_pattern == '<title>Page Restricted</title>\r'

        before_rows = []
        for r in lines:
            j = json.loads(r)
            if ".*" not in j["pattern"]:
                j["pattern"] = unescape_regexp(j["pattern"])
            before_rows.append(j)

        with open("tests/test-out.csv", "w", newline="", encoding="utf-8") as out_file:
            writer = csv.DictWriter(out_file, fieldnames=["fingerprint", "pattern"])
            writer.writeheader()
            writer.writerows(before_rows)

        after_rows = []
        with open("tests/test-out.csv", "r", newline="", encoding="utf-8") as in_file:
            reader = csv.DictReader(in_file)
            for row in reader:
                after_rows.append(row)

        for idx, row in enumerate(after_rows):
            if row != before_rows[idx]:
                assert row == before_rows[idx], f"ERR: {row} != {before_rows[idx]}"

        os.unlink("tests/test-out.csv")
