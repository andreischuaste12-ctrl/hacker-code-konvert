# Mixed review corpus

`app.py` and `plugin.php` were written during an independent audit, before the rule pack was
extended, as a list of common vulnerable patterns. Only the import block of `app.py` was reordered to
satisfy the project linter; the patterns are unchanged, so the measurement is not tuned to the rules. `expected.json` records each expected candidate by rule, file and line, and
lists the pattern the rules are known to miss under `known_gaps`.

All content is synthetic. Nothing here is a real credential or a real application.
