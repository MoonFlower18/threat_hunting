import stix2
indicators = []
with open('hosts.txt') as f:
    for domain in f:
        domain = domain.strip()
        if not domain:
            continue
        try:
            indicator = stix2.Indicator(
                name=f'Malicious Domain: {domain}',
                pattern="[domain-name:value = '{}']".format(domain),
                pattern_type="stix",
                labels=['malicious host']
            )
            indicators.append(indicator)
        except stix2.exceptions.InvalidValueError:
            print(domain)
            continue
bundle = stix2.Bundle(objects=indicators)
with open('malicious_domains.stix', 'w') as f:
    f.write(bundle.serialize(indent=4))