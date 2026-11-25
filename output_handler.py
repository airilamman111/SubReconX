from datetime import datetime, timezone
import json
import os
import re


def save_local_results(recon_data, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9.-]", "_", recon_data.get("target", "unknown"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"subreconx_{safe_target}_{stamp}"

    json_path = os.path.join(output_dir, f"{base_name}.json")
    txt_path = os.path.join(output_dir, f"{base_name}.txt")

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(recon_data, jf, indent=2)

    with open(txt_path, "w", encoding="utf-8") as tf:
        tf.write("SubReconX Passive OSINT Report\n")
        tf.write(f"Target Scope : {recon_data.get('target')}\n")
        tf.write(f"Timestamp UTC: {recon_data.get('timestamp_utc')}\n")
        tf.write(f"Dry-Run Mode : {recon_data.get('dry_run')}\n")
        tf.write("-" * 50 + "\n")
        subdomains = recon_data.get("subdomains", [])
        tf.write(f"Total Unique Subdomains: {len(subdomains)}\n\n")
        for item in subdomains:
            tf.write(f"- {item.get('hostname')}\n")
            if "dns" in item:
                tf.write(f"    DNS: {item['dns']}\n")
        if recon_data.get("errors"):
            tf.write("\nWarnings / Errors:\n")
            for err in recon_data["errors"]:
                tf.write(f"  * {err}\n")

    return json_path, txt_path


if __name__ == "__main__":
    sample_payload = {
        "target": "example.com",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dry_run": True,
        "subdomains": [{"hostname": "www.example.com"}],
        "errors": [],
    }
    j_file, t_file = save_local_results(sample_payload)
    print(f"Saved JSON report: {j_file}")
    print(f"Saved TXT report : {t_file}")