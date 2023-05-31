import os
from kestrel.session import Session


def analyze_stix_bundle():
    with Session(debug_mode=False) as session:
        session.execute(
            f"""
            test =  GET network-traffic
                    FROM file:///{os.getcwd()}/.data/sample_stix_bundle.json
                    WHERE src_port = 443 AND request_method NOT IN ('GET', 'POST')
            """
        )
        var = session.get_variable("test")
        print(var)
        session.close()


if __name__ == "__main__":
    analyze_stix_bundle()
