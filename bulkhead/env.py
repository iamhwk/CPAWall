"""Environment variables that point common clients at a CA and a proxy.

Clients disagree on which variables they read: OpenSSL-based ones (Python,
curl) read SSL_CERT_FILE, git reads GIT_SSL_CAINFO, Node adds
NODE_EXTRA_CA_CERTS, and so on. Setting all of them is how a partition is
made to trust Bulkhead's CA, and how the baseline's machine trusts the
testbed's.
"""
CA_VARS = ("SSL_CERT_FILE", "GIT_SSL_CAINFO", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
           "NODE_EXTRA_CA_CERTS")
PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "all_proxy")
NO_PROXY_VARS = ("no_proxy", "NO_PROXY")


def trust_env(bundle):
    return {var: bundle for var in CA_VARS}


def proxy_env(url):
    env = {var: url for var in PROXY_VARS}
    env.update({var: "" for var in NO_PROXY_VARS})
    return env
