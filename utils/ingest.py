import base64
import gc
import json
import jsonlines
import numpy as np
from app.transform import handler


def load_sample_records(file_path):
    records = []
    with jsonlines.open(file_path) as reader:
        for record in reader:
            records.append(
                {
                    "kinesis": {
                        "data": base64.b64encode(json.dumps(record).encode()).decode()
                    }
                }
            )
    return records


def split_records(records, num_parts):
    return np.array_split(records, num_parts)


records = load_sample_records(file_path=".data/sample_waf_logs.jsonl")
splitted_records = split_records(records, 25)

for i, batch in enumerate(splitted_records, 1):
    event = {"Records": batch.tolist()}
    result = handler(event, None)

    if result is not None:
        stix_bundle = json.loads(result)
        with open(f".data/bundles/sample_stix_bundle{i}.json", "w") as outfile:
            json.dump(stix_bundle, outfile, indent=2)
        gc.collect()
        print(f"Result written to stix_bundle{i}.json")
    else:
        print(f"No bundle to process for batch {i}.")
