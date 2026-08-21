# Optional wheels for the SOAR IDE runtime.

Do not ship `requests` (or charset_normalizer binary wheels) unless Ping fails
with `No module named 'requests'`. Working V1 integrations such as Flare rely
on the tenant runtime’s existing HTTP stack. A mismatched manylinux `.so` in
this folder can itself cause a generic Import Error.
