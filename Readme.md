# Blocking Fingerprints

The goal of this repo is to document all the known blocking fingerprints for
use in network measurement projects aimed at measuring internet censorship.

The sources of these fingerprints are:
* [ooni/pipeline](https://github.com/ooni/pipeline/blob/master/af/fastpath/fastpath/utils.py)
* [censoredplanet/censoredplanet-analysis](https://github.com/censoredplanet/censoredplanet-analysis/tree/master/pipeline/metadata/data)
* [citizenlab/filtering-annotations](https://github.com/citizenlab/filtering-annotations)

In here you will find two CSV files for HTTP and DNS fingerprints respectively.

## Schema

* `name` is an identifier of this particular fingerprint. They are generally in the form of `org.fingerprint_id` (ex. `ooni_br_1`)
* `location_found` indicates where the fingerprint can be found. If we are searching for it in the HTTP response body we will use the key `body`, while if we are looking for it inside of a header it will take the form `header.{header_name}` where `{header_name}` is the header field name in lowercase (ex. `header.x-app-url`). In the case of DNS fingerprints, this will have the value `dns`.
* `pattern_type` indicates what sort of pattern matching should be used, it can be one of `full`, if it's a full strict match (i.e. `==`), `prefix` if we are matching against the prefix of the target value (i.e. `startswith`), `contains` if we are searching for the pattern substring inside of the target (i.e. `is in`), `regexp` if the pattern should be interpreted as a regular expression.
* `pattern` is the value of the pattern used to match. See `pattern_type` for the possible types of patterns.
* `scope`, we currently follow the same definition of scopes used by the citizenlab, which is, `nat` national level blockpage, `isp` ISP level blockpage, `prod` text pattern related to a middlebox product, `inst` text pattern related to a voluntary instition blockpage (school, office), `vbw` vague blocking word, `fp` fingerprint for false positives.
* `confidence_no_fp`, taken also from citizenalb: how likely (by self-assessment) the signature is to cause a false positive. Shorter or more vague text patterns which may be likely to match against are given lower numbers.
* `expected_countries`, a list of countries where we expect to see the blockpage fingerprints comma separated (ex. `IT, IR`).
* `source`, this indicates where this fingerprint came from
* `exp_url`, a link to an OONI Explorer measurement documenting this fingerprint
* `notes`, additional freeform notes on the fingerprint
* `other_names`, a list of other names identifying the fingerprint when it's present in multiple repositories
