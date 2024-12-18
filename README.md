
# **TFE AAP Integration Proxy**

This project is a **Flask-based proxy application** designed to integrate **Terraform Enterprise (TFE)** with **Ansible Automation Platform (AAP)**. It provides a webhook endpoint for TFE, triggers playbook runs in AAP, and polls AAP for job statuses, sending updates back to TFE.

---

## **Features**
- Validates webhook requests from TFE using HMAC.
- Triggers AAP playbooks for TFE run tasks.
  - Passes the TFE run_id as an AAP run specific variable (useful if the AAP task needs to know the TFE run)
- Polls AAP for job statuses with configurable intervals.
- Sends job updates back to TFE, including final outcomes (`success`, `failed`).

---

## **Requirements**
- **Python**: `3.9+`
- **Terraform Enterprise (TFE)`**
- **Ansible Automation Platform (AAP)**: `4.x`

---

## **Setup**

### **1. Install Dependencies**
```bash
pip install -r requirements.txt
```

### **2. Environment Variables**

Configure the following environment variables for the application:

| Variable                   | Description                                                                 | Required | Default Value                                                            |
|----------------------------|-----------------------------------------------------------------------------|----------|--------------------------------------------------------------------------|
| `AAP_AUTH`                 | Base64-encoded credentials for AAP API (`username:password`).               | Yes      | N/A                                                                      |
| `AAP_JOB_TEMPLATE_ID`      | ID of the AAP job template to be triggered.                                 | Yes      | N/A                                                                      |
| `AAP_HOST`                 | Hostname of the AAP instance (e.g., `aap.local`).                           | Yes      | N/A                                                                      |
| `HMAC_KEY`                 | HMAC key for validating incoming requests from TFE.                         | Yes      | N/A                                                                      |
| `HELP_URL`                 | Help URL sent in TFE callback responses.                                    | No       | `https://developer.hashicorp.com/terraform/enterprise/workspaces/settings/run-tasks` |
| `JOB_WAIT_SECONDS`         | Maximum time (in seconds) to poll AAP for job status.                       | No       | `60`                                                                     |
| `JOB_POLLING_INTERVAL_SECONDS` | Polling interval (in seconds) for checking job status.                   | No       | `5`                                                                      |
| `INSECURE`                 | Set to `true` to disable SSL verification for all API calls.                | No       | `false`                                                                  |
| `CERT_FILE`                | Path to the TLS certificate file for Flask.                                 | No       | `/opt/app-root/src/certs/tls.crt`                                        |
| `KEY_FILE`                 | Path to the TLS private key file for Flask.                                 | No       | `/opt/app-root/src/certs/tls.key`                                        |
| `COMBINED_FILE`            | Path to the combined TLS cert+key file for AAP API calls.                   | No       | `/opt/app-root/src/certs/combined.crt`                                   |

### **3. Run the Application**
```bash
python webhook_proxy.py
```

The application will start on `http://0.0.0.0:5000` (or `https://0.0.0.0:5000` if SSL is enabled).

---

## **Endpoints**

### **Webhook Endpoint**

**`POST /webhook/tfe-analytics/run-task`**

#### **Request**
- **Headers**:
  - `x-tfc-task-signature`: HMAC signature for request validation.
- **Body**:
  ```json
  {
    "run_id": "run-12345",
    "task_result_callback_url": "https://tfe.local/api/v2/task-results/12345/callback",
    "access_token": "Bearer <token>"
  }
  ```

#### **Response**
- **200**: Playbook triggered successfully.
- **400**: Invalid request data.
- **401**: HMAC validation failed.
- **500**: Failed to trigger playbook or process request.

---

## **How It Works**
1. **TFE Webhook**:
   - TFE sends a POST request to the `/webhook/tfe-analytics/run-task` endpoint with details about the Terraform run.
   - The request is validated using an HMAC key.

2. **Trigger AAP Playbook**:
   - The application triggers a job template in AAP using the provided run ID.
   - If the playbook is triggered successfully, it retrieves the `job_id` from AAP.

3. **Poll AAP Status**:
   - The app periodically polls the AAP API for job status updates using the `job_id`.
   - If the job status is `successful` or `failed`, it sends a corresponding callback to TFE.

4. **Callback to TFE**:
   - The app sends updates back to TFE using the `task_result_callback_url` with the job status (`running`, `passed`, or `failed`).

