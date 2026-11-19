# cloudflare example

A hub with no AWS WAF resources: the table, the reconciler and one Cloudflare
custom IP list it keeps in sync. The list and the zone rule that blocks on it
live wherever the Cloudflare configuration is managed; this example only takes
their IDs. Put the API token in the secret by hand after the first apply.
