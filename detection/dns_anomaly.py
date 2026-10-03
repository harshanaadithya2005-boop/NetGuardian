def is_unusually_long_domain(domain, max_length=50):
    return len(domain) > max_length
domain = "this-is-a-very-long-example-domain-name-for-testing.example"

if is_unusually_long_domain(domain):
    print("DNS anomaly detected")