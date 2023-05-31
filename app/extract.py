import boto3
import json
import traceback
from tqdm import tqdm

s3 = boto3.client("s3")

bucket_name = "waf-central-logging-input"
prefix = "2023/05/27/20/"
merge_file_name = ".data/sample_waf_logs.jsonl"

paginator = s3.get_paginator("list_objects_v2")
pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

total_files = 0
for page in pages:
    total_files += len(page["Contents"])

progress_bar = tqdm(
    total=total_files, ncols=75, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
)
pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

merged_data = []
for page in pages:
    for obj in page["Contents"]:
        file_key = obj["Key"]
        try:
            file_object = s3.get_object(Bucket=bucket_name, Key=file_key)
            file_content = file_object["Body"].read().decode("utf-8")
            lines = file_content.strip().split("\n")
            for line in lines:
                json_line = json.loads(line)
                merged_data.append(json_line)
            progress_bar.update(1)
        except Exception as e:
            print(f"Error processing file: {file_key}")
            print(traceback.format_exc())

merged_file_content = "\n".join(json.dumps(line) for line in merged_data)
with open(merge_file_name, "w") as outfile:
    outfile.write(merged_file_content)
