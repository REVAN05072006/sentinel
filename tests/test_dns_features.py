from backend.features.dns_features import DNSFeatureExtractor


queries = [
    "www.google.com",
    "api.github.com",
    "mail.microsoft.com",
    "xq7mz91k2p8v4n6b.example.com",
    "ajd83kq91mz7x2p9v4.example.net",
]


for query in queries:
    features = DNSFeatureExtractor.extract(query)

    print(f"\nQUERY: {query}")
    print(f"Length: {features.query_length}")
    print(f"Labels: {features.label_count}")
    print(f"Max label length: {features.max_label_length}")
    print(f"Average label length: {features.average_label_length}")
    print(f"Entropy: {features.entropy}")
    print(f"Digit ratio: {features.digit_ratio}")
    print(f"Unique char ratio: {features.unique_char_ratio}")
    print(f"Vowel ratio: {features.vowel_ratio}")
    print(f"Consonant ratio: {features.consonant_ratio}")
    print(f"Hyphen ratio: {features.hyphen_ratio}")
    print(f"Numeric labels: {features.numeric_label_count}")
    print(f"Subdomain depth: {features.subdomain_depth}")