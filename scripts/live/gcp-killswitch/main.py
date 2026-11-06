"""Turns billing off for one test project once its budget says spend reached the limit.

Google Cloud has no hard spending cap. Its budget posts the current cost to Pub/Sub a few
times a day, with a delay, so the limit here sits below what the owner may spend.
Pattern: docs.cloud.google.com/billing/docs/how-to/disable-billing-with-notifications
"""
import base64
import json
import os

import functions_framework
import google.auth
from google.auth.transport.requests import AuthorizedSession

KILL_AT = float(os.environ["KILL_AT"])
PROJECT = os.environ["PROJECT_ID"]
BILLING_INFO = f"https://cloudbilling.googleapis.com/v1/projects/{PROJECT}/billingInfo"


@functions_framework.cloud_event
def on_budget(event):
    notice = json.loads(base64.b64decode(event.data["message"]["data"]))
    cost = float(notice["costAmount"])
    currency = notice.get("currencyCode", "")
    if cost < KILL_AT:
        print(f"under the limit: {cost} {currency} of {KILL_AT}")
        return

    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-billing"])
    answer = AuthorizedSession(credentials).put(BILLING_INFO, json={"billingAccountName": ""}, timeout=30)
    answer.raise_for_status()
    print(f"BILLING DISABLED on {PROJECT}: {cost} {currency} reached {KILL_AT}")
