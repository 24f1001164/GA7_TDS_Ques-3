from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
import re

app = FastAPI(title="Terraform Plan Policy Gate")

# ============================================================
# ASSIGNED VALUES
# ============================================================

PRODUCTION_WORKSPACE = "prod-rgddn5"

REQUIRED_LABELS = {
    "owner": "student-v8ht2",
    "environment": "production",
    "cost_center": "cc-2t6i",
}

ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

ALLOWED_ACTIONS = {
    "create",
    "update",
    "delete",
}

STATEFUL_RESOURCES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


# ============================================================
# RESPONSE HELPERS
# ============================================================

def reject(reason: str):
    return JSONResponse(
        status_code=200,
        content={
            "decision": "reject",
            "reason": reason
        }
    )


def approve():
    return JSONResponse(
        status_code=200,
        content={
            "decision": "approve",
            "reason": "APPROVE"
        }
    )


# ============================================================
# TYPE HELPERS
# ============================================================

def is_string(value: Any) -> bool:
    return isinstance(value, str)


def is_bool(value: Any) -> bool:
    # bool is deliberately checked separately because
    # bool is a subclass of int in Python.
    return type(value) is bool


def is_object(value: Any) -> bool:
    return isinstance(value, dict)


# ============================================================
# 1. REQUEST / NESTED OBJECT TYPE VALIDATION
# ============================================================

def validate_types(data: Any) -> bool:

    if not is_object(data):
        return False

    # Required top-level fields
    required_top_level = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top_level.issubset(data.keys()):
        return False

    # Top-level types
    if not is_string(data["environment"]):
        return False

    if not is_object(data["state"]):
        return False

    if not is_string(data["providerVersion"]):
        return False

    if not is_bool(data["destroyApproved"]):
        return False

    if not is_object(data["resource"]):
        return False

    # State object
    state = data["state"]

    if "backend" not in state:
        return False

    if "locked" not in state:
        return False

    if not is_string(state["backend"]):
        return False

    if not is_bool(state["locked"]):
        return False

    # Resource object
    resource = data["resource"]

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not required_resource.issubset(resource.keys()):
        return False

    if not is_string(resource["address"]):
        return False

    if not is_string(resource["type"]):
        return False

    if not is_string(resource["action"]):
        return False

    if not is_object(resource["labels"]):
        return False

    if resource["secret"] is not None and not is_string(resource["secret"]):
        return False

    if not is_bool(resource["forceDestroy"]):
        return False

    # Labels must be string -> string
    for key, value in resource["labels"].items():
        if not is_string(key) or not is_string(value):
            return False

    return True


# ============================================================
# 2. ENVIRONMENT
# ============================================================

def check_environment(data: dict) -> bool:
    return data["environment"] == PRODUCTION_WORKSPACE


# ============================================================
# 3. STATE SAFETY
# ============================================================

def check_state(data: dict) -> bool:

    state = data["state"]

    if state["backend"] not in ALLOWED_BACKENDS:
        return False

    if state["locked"] is not True:
        return False

    return True


# ============================================================
# 4. PROVIDER PINNING
# ============================================================

def check_provider(provider: str) -> bool:

    # Exact version:
    # 6.2.1
    if provider == "6.2.1":
        return True

    # Exact Terraform constraint:
    # = 6.2.1
    if provider == "= 6.2.1":
        return True

    # Pessimistic constraint:
    # ~> 6.0
    if provider == "~> 6.0":
        return True

    return False


# ============================================================
# 5. REQUIRED LABELS
# ============================================================

def check_labels(labels: dict) -> bool:

    for key, expected_value in REQUIRED_LABELS.items():

        if key not in labels:
            return False

        if labels[key] != expected_value:
            return False

    return True


# ============================================================
# 6. SECRET VALIDATION
# ============================================================

def check_secret(secret: Any) -> bool:

    # null is explicitly allowed
    if secret is None:
        return True

    # Otherwise it must be a non-empty secret:// reference
    if not isinstance(secret, str):
        return False

    if not secret.startswith("secret://"):
        return False

    # secret:// by itself is not valid
    if len(secret) <= len("secret://"):
        return False

    return True


# ============================================================
# 7. DELETE APPROVAL
# ============================================================

def check_delete(resource: dict, destroy_approved: bool) -> bool:

    if resource["action"] != "delete":
        return True

    if resource["type"] not in STATEFUL_RESOURCES:
        return True

    return destroy_approved is True


# ============================================================
# 8. FORCE DESTROY
# ============================================================

def check_force_destroy(data: dict) -> bool:

    resource = data["resource"]

    if (
        data["environment"] == PRODUCTION_WORKSPACE
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return False

    return True


# ============================================================
# MAIN ENDPOINT
# ============================================================

@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    # Parse JSON safely
    try:
        data = await request.json()
    except Exception:
        return reject("INVALID_PLAN")

    # --------------------------------------------------------
    # RULE 1: TYPES
    # --------------------------------------------------------

    if not validate_types(data):
        return reject("INVALID_PLAN")

    # --------------------------------------------------------
    # RULE 2: ENVIRONMENT
    # --------------------------------------------------------

    if not check_environment(data):
        return reject("ENVIRONMENT_MISMATCH")

    # --------------------------------------------------------
    # RULE 3: STATE
    # --------------------------------------------------------

    if not check_state(data):
        return reject("STATE_UNSAFE")

    # --------------------------------------------------------
    # RULE 4: PROVIDER
    # --------------------------------------------------------

    if not check_provider(data["providerVersion"]):
        return reject("UNPINNED_PROVIDER")

    # --------------------------------------------------------
    # RULE 5: LABELS
    # --------------------------------------------------------

    if not check_labels(data["resource"]["labels"]):
        return reject("MISSING_LABELS")

    # --------------------------------------------------------
    # RULE 6: SECRET
    # --------------------------------------------------------

    if not check_secret(data["resource"]["secret"]):
        return reject("PLAINTEXT_SECRET")

    # --------------------------------------------------------
    # RULE 7: DELETE APPROVAL
    # --------------------------------------------------------

    if not check_delete(
        data["resource"],
        data["destroyApproved"]
    ):
        return reject("DELETE_NOT_APPROVED")

    # --------------------------------------------------------
    # RULE 8: FORCE DESTROY
    # --------------------------------------------------------

    if not check_force_destroy(data):
        return reject("FORCE_DESTROY")

    # --------------------------------------------------------
    # ALL RULES PASSED
    # --------------------------------------------------------

    return approve()


@app.get("/")
async def root():
    return {
        "service": "Terraform Plan Policy Gate",
        "status": "ok"
    }
