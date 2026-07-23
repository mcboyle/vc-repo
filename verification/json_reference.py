#!/usr/bin/env python3
# json_reference.py — validates the C --json output using python's own parser (ROI item 48).
#   default:  every line is valid JSON, values round-trip, and the hostile string is escaped
#             (round-trips exactly, no injected top-level key).
#   --negctl: the SAME hostile line, emitted WITHOUT escaping, must FAIL to round-trip cleanly
#             (invalid JSON, or an injected field, or a truncated value) — proving escaping is needed.
import sys, json

NASTY = 'a"b\\c\n\td",\"injected\":\"pwned'

def main():
    negctl = "--negctl" in sys.argv
    lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
    if len(lines) < 2:
        print("FAIL: expected 2 JSON lines, got %d" % len(lines)); return 1

    # line 1: status object — must always be valid regardless of mode
    try:
        st = json.loads(lines[0])
    except Exception as e:
        print("FAIL: status line is not valid JSON: %s" % e); return 1
    if st.get("status") != "wrong_password" or st.get("code") != 77 or st.get("ok") is not False:
        print("FAIL: status object fields wrong: %r" % st); return 1
    print("OK: status object is valid JSON with the expected fields")

    # line 2: the hostile-value object
    if not negctl:
        try:
            obj = json.loads(lines[1])
        except Exception as e:
            print("FAIL: escaped hostile value did not parse: %s" % e); return 1
        if "injected" in obj:
            print("FAIL: injection succeeded despite escaping (top-level 'injected' present)"); return 1
        if obj.get("label") != NASTY:
            print("FAIL: hostile value did not round-trip exactly"); return 1
        if obj.get("n") != len(NASTY):
            print("FAIL: length field mismatch"); return 1
        print("OK: hostile value is escaped, round-trips exactly, and injects nothing")
        return 0
    else:
        # negative control: the naive output must NOT be a clean, injection-free round-trip
        broke = False; reason = ""
        try:
            obj = json.loads(lines[1])
            if "injected" in obj:
                broke = True; reason = "field injection succeeded"
            elif obj.get("label") != NASTY:
                broke = True; reason = "value corrupted / did not round-trip"
        except Exception as e:
            broke = True; reason = "invalid JSON (%s)" % type(e).__name__
        if broke:
            print("OK (neg-control): unescaped output is broken as expected -> %s" % reason); return 0
        print("FAIL (neg-control): unescaped output somehow round-tripped cleanly"); return 1

if __name__ == "__main__":
    sys.exit(main())
