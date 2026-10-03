def is_unusually_long_domain(domain, max_length=50):
    return len(domain) > max_length
domain = "this-is-a-very-long-example-domain-name-for-testing.example"

if is_unusually_long_domain(domain):
    print("DNS anomaly detected")
    
    
def detect_repeated_failures(failed_queries, threshold=5):
    return failed_queries >= threshold

failed_queries = 7

if detect_repeated_failures(failed_queries):
    print("Repeated DNS query failures detected")