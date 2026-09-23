
import requests
import urllib3
import yaml

# ============================================================
# SSL
# ============================================================
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

# ============================================================
# Configuration
# ============================================================
MDS_SERVER = "192.168.0.230"
CMA_SERVER = "192.168.0.235"
EXPECTED_DOMAIN = "Domain001"
DEFAULT_POLICY_PACKAGE = "Domain001_Policypackage"
DEFAULT_TARGET = "FW01"
DEFAULT_LAYER = "Network"

# ============================================================
# YAML
# ============================================================
def load_yaml(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}

# ============================================================
# Check Point Login
# ============================================================
def login_to_checkpoint(session, config, domain):
    server = str(
        config.get(
            "server",
            MDS_SERVER,
        )
    ).strip()
    username = str(
        config["username"]
    ).strip()
    password = str(
        config["password"]
    ).strip()
    url = f"https://{server}/web_api/login"
    payload = {
        "user": username,
        "password": password,
        "domain": domain,
    }
    print()
    print("🔐 Authenticating to Check Point...")
    print(f"   MDS:    {server}")
    print(f"   Domain: {domain}")
    print(f"   User:   {username}")
    response = session.post(
        url,
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        verify=False,
        timeout=30,
    )
    if response.status_code >= 400:
        print()
        print(
            f"❌ Login failed: HTTP "
            f"{response.status_code}"
        )
        print(response.text)
        response.raise_for_status()
    result = response.json()
    sid = result.get("sid")
    if not sid:
        raise RuntimeError(
            "Login succeeded but no SID was returned:\n"
            f"{result}"
        )
    print()
    print("✅ Authentication successful.")
    print(
        "   API version: "
        f"{result.get('api-server-version', 'unknown')}"
    )
    print(
        f"   SID: {sid[:8]}..."
    )
    return sid

# ============================================================
# Generic API Call
# ============================================================
def api_call(
    session,
    server,
    sid,
    command,
    payload=None,
):
    url = (
        f"https://{server}"
        f"/web_api/{command}"
    )
    if payload is None:
        payload = {}
    response = session.post(
        url,
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-chkp-sid": sid,
        },
        verify=False,
        timeout=120,
    )
    if response.status_code >= 400:
        print()
        print(
            "❌ API command failed"
        )
        print(
            f"   Command: {command}"
        )
        print(
            f"   Server:  {server}"
        )
        print(
            f"   HTTP:    {response.status_code}"
        )
        print(
            f"   Payload: {payload}"
        )
        print()
        print(response.text)
        response.raise_for_status()
    try:
        return response.json()
    except ValueError:
        return {
            "raw_response": response.text
        }

# ============================================================
# Logout
# ============================================================
def logout(
    session,
    server,
    sid,
):
    try:
        api_call(
            session,
            server,
            sid,
            "logout",
            {},
        )
        print()
        print("🔒 API session closed.")
    except Exception as exc:
        print(
            f"⚠️ Logout warning: {exc}"
        )

# ============================================================
# Access Layer Discovery
# ============================================================
def discover_access_layers(
    session,
    server,
    sid,
):
    print()
    print(
        "🔎 Discovering Access Control layers..."
    )
    payload = {
        "limit": 50,
        "offset": 0,
        "details-level": "standard",
    }
    result = api_call(
        session,
        server,
        sid,
        "show-access-layers",
        payload,
    )
    # IMPORTANT:
    # Check Point returns the list under
    # "access-layers", NOT "layers".
    layers = result.get(
        "access-layers",
        [],
    )
    print()
    print(
        "Raw access-layer response:"
    )
    print(
        result
    )
    if not layers:
        raise RuntimeError(
            "No Access Control layers were returned "
            "by show-access-layers.\n\n"
            f"API response:\n{result}"
        )
    print()
    print(
        "Available Access Control layers:"
    )
    names = []
    for layer in layers:
        name = layer.get(
            "name"
        )
        if name:
            names.append(name)
            print(
                f"   - {name}"
            )
    return names

# ============================================================
# Resolve Access Layer
# ============================================================
def resolve_layer_name(
    policy,
    layer_names,
):
    requested = str(
        policy.get(
            "layer",
            DEFAULT_LAYER,
        )
    ).strip()
    if requested in layer_names:
        print()
        print(
            f"✅ Access layer selected: "
            f"{requested}"
        )
        return requested
    # Try common alternatives if the configured
    # name does not exist.
    alternatives = [
        DEFAULT_LAYER,
        "Standard",
        "Default Layer",
    ]
    for candidate in alternatives:
        if candidate in layer_names:
            print()
            print(
                f"⚠️ Configured layer "
                f"'{requested}' was not found."
            )
            print(
                f"   Using discovered layer: "
                f"{candidate}"
            )
            return candidate
    raise RuntimeError(
        "Could not resolve Access Control layer.\n"
        f"Configured layer: {requested}\n"
        f"Available layers: {layer_names}"
    )

# ============================================================
# Add Host
# ============================================================
def add_host(
    session,
    server,
    sid,
    host,
):
    name = host["name"]
    ip = host["ip"]
    print()
    print(
        f"➕ Adding host: "
        f"{name} ({ip})"
    )
    payload = {
        "name": name,
        "ip-address": ip,
    }
    try:
        result = api_call(
            session,
            server,
            sid,
            "add-host",
            payload,
        )
        print(
            f"✅ Host created: {name}"
        )
        return result
    except requests.HTTPError as exc:
        response = exc.response
        if (
            response is not None
            and response.status_code == 400
            and (
                "already exists"
                in response.text.lower()
                or "generic_err_object_already_exists"
                in response.text
            )
        ):
            print(
                f"ℹ️ Host already exists: {name}"
            )
            return {
                "name": name,
                "existing": True,
            }
        raise

# ============================================================
# Add Network
# ============================================================
def add_network(
    session,
    server,
    sid,
    network,
):
    name = network["name"]
    subnet = network["subnet"]
    mask = network["mask"]
    print()
    print(
        f"➕ Adding network: "
        f"{name} ({subnet}/{mask})"
    )
    payload = {
        "name": name,
        "subnet": subnet,
        "mask": mask,
    }
    try:
        result = api_call(
            session,
            server,
            sid,
            "add-network",
            payload,
        )
        print(
            f"✅ Network created: {name}"
        )
        return result
    except requests.HTTPError as exc:
        response = exc.response
        if (
            response is not None
            and response.status_code == 400
            and (
                "already exists"
                in response.text.lower()
                or "generic_err_object_already_exists"
                in response.text
            )
        ):
            print(
                f"ℹ️ Network already exists: "
                f"{name}"
            )
            return {
                "name": name,
                "existing": True,
            }
        raise

# ============================================================
# Add Access Rule
# ============================================================
def add_access_rule(
    session,
    server,
    sid,
    layer_name,
    rule,
):
    name = rule["name"]
    position = rule.get(
        "position",
        "top",
    )
    action = rule["action"]
    print()
    print(
        f"➕ Adding access rule: "
        f"{name}"
    )
    print(
        f"   Layer:    {layer_name}"
    )
    print(
        f"   Position: {position}"
    )
    print(
        f"   Action:   {action}"
    )
    payload = {
        "layer": layer_name,
        # REQUIRED by Check Point API.
        "position": position,
        "name": name,
        "action": action,
        "source": rule.get(
            "source",
            [],
        ),
        "destination": rule.get(
            "destination",
            [],
        ),
        "service": rule.get(
            "service",
            [],
        ),
    }
    print(
        f"   Source:      "
        f"{payload['source']}"
    )
    print(
        f"   Destination: "
        f"{payload['destination']}"
    )
    print(
        f"   Service:     "
        f"{payload['service']}"
    )
    try:
        result = api_call(
            session,
            server,
            sid,
            "add-access-rule",
            payload,
        )
        print(
            f"✅ Access rule created: "
            f"{name}"
        )
        return result
    except requests.HTTPError as exc:
        response = exc.response
        if (
            response is not None
            and response.status_code == 400
            and (
                "already exists"
                in response.text.lower()
            )
        ):
            print(
                f"ℹ️ Access rule may already "
                f"exist: {name}"
            )
            return {
                "name": name,
                "existing": True,
            }
        raise

# ============================================================
# Publish
# ============================================================
def publish_changes(
    session,
    server,
    sid,
):
    print()
    print(
        "💾 Publishing changes..."
    )
    result = api_call(
        session,
        server,
        sid,
        "publish",
        {},
    )
    print(
        "✅ Changes published."
    )
    return result

# ============================================================
# Install Policy
# ============================================================
def install_policy(
    session,
    server,
    sid,
    package,
    target,
):
    print()
    print(
        "=============================================="
    )
    print(
        " 📡 INSTALL POLICY"
    )
    print(
        "=============================================="
    )
    print(
        f"   Policy package: {package}"
    )
    print(
        f"   Target:         {target}"
    )
    # IMPORTANT:
    # Explicitly specify BOTH the policy package
    # and the Security Gateway target.
    #
    # This prevents the API request from attempting
    # to install "Standard" on FW01.
    payload = {
        "policy-package": package,
        "targets": [
            target
        ],
    }
    print()
    print(
        "Install payload:"
    )
    print(
        payload
    )
    result = api_call(
        session,
        server,
        sid,
        "install-policy",
        payload,
    )
    print()
    print(
        "✅ Policy installation request "
        "accepted by the API."
    )
    return result

# ============================================================
# Main
# ============================================================
def main():
    # --------------------------------------------------------
    # Load YAML files
    # --------------------------------------------------------
    config = load_yaml(
        "config.yml"
    )
    policy = load_yaml(
        "policy.yml"
    )
    if not config:
        raise RuntimeError(
            "config.yml is empty."
        )
    if not policy:
        raise RuntimeError(
            "policy.yml is empty."
        )
    # --------------------------------------------------------
    # Domain
    # --------------------------------------------------------
    configured_domain = str(
        policy.get(
            "domain",
            config.get(
                "domain",
                EXPECTED_DOMAIN,
            ),
        )
    ).strip()
    if configured_domain != EXPECTED_DOMAIN:
        raise RuntimeError(
            "Incorrect domain.\n"
            f"Expected: {EXPECTED_DOMAIN}\n"
            f"Found:    {configured_domain}"
        )
    # --------------------------------------------------------
    # Policy package
    # --------------------------------------------------------
    package = str(
        policy.get(
            "policy_package",
            DEFAULT_POLICY_PACKAGE,
        )
    ).strip()
    if not package:
        package = DEFAULT_POLICY_PACKAGE
    # --------------------------------------------------------
    # Installation target
    # --------------------------------------------------------
    target = str(
        policy.get(
            "target",
            DEFAULT_TARGET,
        )
    ).strip()
    if not target:
        target = DEFAULT_TARGET
    # --------------------------------------------------------
    # Safety check
    # --------------------------------------------------------
    #
    # We do NOT want the lab automation accidentally
    # installing Standard on FW01.
    # --------------------------------------------------------
    if package == "Standard":
        raise RuntimeError(
            "SAFETY CHECK FAILED:\n"
            "policy.yml specifies the 'Standard' "
            "policy package.\n\n"
            "This deployment is configured for "
            f"'{DEFAULT_POLICY_PACKAGE}'.\n\n"
            "Change policy_package in policy.yml "
            "before running the deployment."
        )
    # --------------------------------------------------------
    # Display deployment information
    # --------------------------------------------------------
    print()
    print(
        "=============================================="
    )
    print(
        " Check Point Lab Deployment"
    )
    print(
        "=============================================="
    )
    print(
        f"MDS:             {MDS_SERVER}"
    )
    print(
        f"Domain:          {configured_domain}"
    )
    print(
        f"CMA:             {CMA_SERVER}"
    )
    print(
        f"Policy Package:  {package}"
    )
    print(
        f"Install Target:  {target}"
    )
    print(
        "=============================================="
    )
    # --------------------------------------------------------
    # API session
    # --------------------------------------------------------
    with requests.Session() as session:
        sid = None
        try:
            # =================================================
            # LOGIN
            # =================================================
            sid = login_to_checkpoint(
                session,
                config,
                configured_domain,
            )
            print()
            print(
                "🚀 Starting deployment..."
            )
            # =================================================
            # DISCOVER ACCESS LAYERS
            # =================================================
            layer_names = (
                discover_access_layers(
                    session,
                    CMA_SERVER,
                    sid,
                )
            )
            layer_name = (
                resolve_layer_name(
                    policy,
                    layer_names,
                )
            )
            # =================================================
            # HOSTS
            # =================================================
            hosts = policy.get(
                "hosts",
                [],
            )
            for host in hosts:
                add_host(
                    session,
                    CMA_SERVER,
                    sid,
                    host,
                )
            # =================================================
            # NETWORKS
            # =================================================
            networks = policy.get(
                "networks",
                [],
            )
            for network in networks:
                add_network(
                    session,
                    CMA_SERVER,
                    sid,
                    network,
                )
            # =================================================
            # ACCESS RULES
            # =================================================
            rules = policy.get(
                "rules",
                [],
            )
            for rule in rules:
                add_access_rule(
                    session,
                    CMA_SERVER,
                    sid,
                    layer_name,
                    rule,
                )
            # =================================================
            # PUBLISH
            # =================================================
            publish_result = (
                publish_changes(
                    session,
                    CMA_SERVER,
                    sid,
                )
            )
            print()
            print(
                "Publish response:"
            )
            print(
                publish_result
            )
            # =================================================
            # INSTALL POLICY
            # =================================================
            install_result = (
                install_policy(
                    session,
                    CMA_SERVER,
                    sid,
                    package,
                    target,
                )
            )
            print()
            print(
                "Install response:"
            )
            print(
                install_result
            )
            # =================================================
            # COMPLETE
            # =================================================
            print()
            print(
                "=============================================="
            )
            print(
                " 🏁 DEPLOYMENT COMPLETE"
            )
            print(
                "=============================================="
            )
            print()
            print(
                f"Policy package: {package}"
            )
            print(
                f"Gateway:        {target}"
            )
            print(
                f"Domain:         {configured_domain}"
            )
            print(
                f"Access layer:   {layer_name}"
            )
            print()
        except Exception as exc:
            print()
            print(
                "=============================================="
            )
            print(
                " ❌ DEPLOYMENT FAILED"
            )
            print(
                "=============================================="
            )
            print(
                f"{exc}"
            )
            raise
        finally:
            # =================================================
            # LOGOUT
            # =================================================
            if sid:
                logout(
                    session,
                    CMA_SERVER,
                    sid,
                )

# ============================================================
# Entry Point
# ============================================================
if __name__ == "__main__":
    main()
