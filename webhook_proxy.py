import concurrent.futures
import hashlib
import hmac
import json
import logging
import os
import time
from flask import Flask, request, jsonify, abort, make_response
import requests

# ---- Configuration and Constants ----
DEFAULT_JOB_WAIT_SECONDS = 60
DEFAULT_POLLING_INTERVAL = 5

# Flask app initialization
app = Flask(__name__)

# Setup logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}'
)
app.logger.setLevel(LOG_LEVEL)

# Environment variables
AAP_AUTH = os.getenv("AAP_AUTH")
AAP_JOB_TEMPLATE_ID = os.getenv("AAP_JOB_TEMPLATE_ID")
AAP_HOST = os.getenv("AAP_HOST")
HMAC_KEY = os.getenv("HMAC_KEY")
HELP_URL = os.getenv(
    "HELP_URL",
    "https://developer.hashicorp.com/terraform/enterprise/workspaces/settings/run-tasks"
)
JOB_WAIT_SECONDS = int(os.getenv("JOB_WAIT_SECONDS", DEFAULT_JOB_WAIT_SECONDS))
JOB_POLLING_INTERVAL_SECONDS = int(os.getenv("JOB_POLLING_INTERVAL", DEFAULT_POLLING_INTERVAL))
INSECURE = os.getenv("INSECURE", "false").lower() == "true"

# Certificate and key files for SSL/TLS
CERT_FILE = os.getenv("CERT_FILE", "/opt/app-root/src/certs/tls.crt")
KEY_FILE = os.getenv("KEY_FILE", "/opt/app-root/src/certs/tls.key")
COMBINED_FILE = os.getenv("COMBINED_FILE", "/opt/app-root/src/certs/combined.crt")

AAP_URL = f"https://{AAP_HOST}/api/v2/job_templates/{AAP_JOB_TEMPLATE_ID}/launch"

# Validate environment variables
REQUIRED_ENV_VARS = ["AAP_AUTH", "AAP_JOB_TEMPLATE_ID", "AAP_HOST", "HMAC_KEY"]
for env_var in REQUIRED_ENV_VARS:
    if not os.getenv(env_var):
        app.logger.error(f"Missing required environment variable: {env_var}")
        raise ValueError(f"Missing required environment variable: {env_var}")

# ThreadPoolExecutor for managing polling threads
executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

# ---- Webhook Endpoint ----
@app.route("/webhook/tfe-analytics/run-task", methods=["POST"])
def webhook():
    """Handles incoming POST requests from TFE."""
    payload = request.get_data()
    signature = request.headers.get("x-tfc-task-signature")

    # Validate HMAC
    if not hmac_digest_is_valid(payload, signature):
        app.logger.error("HMAC validation failed.")
        return make_response(jsonify({"error": "HMAC validation failed"}), 401)

    try:
        event = json.loads(payload.decode("utf-8"))
        run_id = event.get("run_id")
        callback_url = event.get("task_result_callback_url")
        access_token = event.get("access_token")
        if not run_id or not callback_url or not access_token:
            raise ValueError("Missing run_id, task_result_callback_url, or access_token.")
    except (json.JSONDecodeError, ValueError) as e:
        app.logger.error(f"Payload parsing error: {e}")
        return make_response(jsonify({"error": "Invalid JSON or missing data"}), 400)

    # Trigger AAP playbook
    response = trigger_aap_playbook(run_id)
    if response and response.status_code == 201:
        app.logger.info(f"Playbook triggered successfully for run_id {run_id}.")
        job_id = response.json().get("id")
        if not job_id:
            app.logger.error("Job ID missing from AAP response.")
            return make_response(jsonify({"error": "Job ID missing from AAP response"}), 500)
        executor.submit(poll_aap_status, job_id, callback_url, access_token)
        return jsonify({"message": "Playbook triggered successfully"}), 200
    else:
        app.logger.error(f"Failed to trigger playbook: {response.status_code} - {response.text}")
        return make_response(jsonify({"error": "Failed to trigger playbook"}), 500)

# ---- Helper Functions ----
def hmac_digest_is_valid(payload: bytes, signature: str) -> bool:
    """Validate HMAC signature."""
    h = hmac.new(bytes(HMAC_KEY, "UTF-8"), payload, hashlib.sha512)
    calculated_digest = h.hexdigest()
    return hmac.compare_digest(calculated_digest, signature)

def trigger_aap_playbook(run_id: str):
    """Trigger an AAP playbook using the AAP API."""
    headers = {
        "Authorization": f"Basic {AAP_AUTH}",
        "Content-Type": "application/json",
    }
    data = {"extra_vars": {"run_id": run_id}}
    try:
        response = requests.post(AAP_URL, headers=headers, json=data, verify=COMBINED_FILE if not INSECURE else False, timeout=10)
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout occurred when triggering playbook at {AAP_URL}")
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error triggering playbook: {e}")
    return None

def poll_aap_status(job_id: str, callback_url: str, access_token: str):
    """Poll AAP status and update TFE."""
    headers = {"Authorization": f"Basic {AAP_AUTH}"}
    status_url = f"https://{AAP_HOST}/api/v2/jobs/{job_id}"
    elapsed_time = 0
    try:
        while elapsed_time < JOB_WAIT_SECONDS:
            response = requests.get(status_url, headers=headers, verify=COMBINED_FILE if not INSECURE else False, timeout=10)
            response.raise_for_status()
            if response.status_code == 200:
                job_status = response.json().get("status")
                if job_status == "successful":
                    send_callback(callback_url, "passed", "Playbook executed successfully.", access_token)
                    return
                elif job_status == "failed":
                    send_callback(callback_url, "failed", "Playbook execution failed.", access_token)
                    return
                else:
                    send_callback(callback_url, "running", f"Task still running for job ID {job_id}.", access_token)
            elapsed_time += JOB_POLLING_INTERVAL_SECONDS
            time.sleep(JOB_POLLING_INTERVAL_SECONDS)
        send_callback(callback_url, "failed", "Job polling timed out.", access_token)
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error polling AAP status: {e}")
        send_callback(callback_url, "failed", "Error polling playbook status.", access_token)

def send_callback(callback_url: str, status: str, message: str, access_token: str):
    """Send status updates to TFE."""
    headers = {
        "Content-Type": "application/vnd.api+json",
        "Authorization": f"Bearer {access_token}"
    }
    data = {
        "data": {
            "type": "task-results",
            "attributes": {
                "status": status,
                "message": message,
                "url": HELP_URL
            }
        }
    }
    try:
        response = requests.patch(callback_url, headers=headers, json=data, verify=COMBINED_FILE if not INSECURE else False, timeout=10)
        response.raise_for_status()
        app.logger.info(f"Callback to TFE succeeded: {message}")
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error sending callback to TFE: {e}")

# ---- Entry Point ----
if __name__ == "__main__":
    if INSECURE:
        app.run(host="0.0.0.0", port=5000)
    else:
        app.run(host="0.0.0.0", port=5000, ssl_context=(CERT_FILE, KEY_FILE))