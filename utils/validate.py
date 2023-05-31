import os
from stix2validator import validate_file, print_results

results = validate_file(f"{os.getcwd()}/.data/sample_stix_bundle.json")
print_results(results)
