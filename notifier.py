import base64
import os
import urllib.parse
import urllib.request


DEFAULT_ALERT_PHONE = "+919680538149"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")


def load_env_file():
    if not os.path.exists(ENV_PATH):
        return

    with open(ENV_PATH, encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if value:
                os.environ[key] = value


load_env_file()


def get_alert_target(channel):
    if channel == "whatsapp":
        return os.getenv("ALERT_WHATSAPP_TO", f"whatsapp:{DEFAULT_ALERT_PHONE}")

    return os.getenv("ALERT_PHONE_NUMBER", DEFAULT_ALERT_PHONE)


def get_sender(channel):
    if channel == "whatsapp":
        return os.getenv("TWILIO_WHATSAPP_FROM")

    return os.getenv("TWILIO_FROM_NUMBER")


def send_agent_alert(url, risk, user):
    channel = os.getenv("ALERT_CHANNEL", "sms").strip().lower()
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    sender = get_sender(channel)

    if not account_sid or not auth_token or not sender:
        print("Agent phone alert skipped: Twilio settings are not configured.")
        return False

    target = get_alert_target(channel)
    body = (
        "ShieldScan alert-zone URL requires verification. "
        f"Risk: {risk}%. URL: {url}. "
        f"User: {user['display_name']} ({user['username']}). "
        "Open the agent monitor to approve it."
    )

    api_url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    payload = urllib.parse.urlencode(
        {
            "From": sender,
            "To": target,
            "Body": body,
        }
    ).encode("utf-8")
    credentials = f"{account_sid}:{auth_token}".encode("utf-8")
    request = urllib.request.Request(api_url, data=payload)
    request.add_header(
        "Authorization",
        f"Basic {base64.b64encode(credentials).decode('ascii')}",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except Exception as error:
        response_body = ""
        if hasattr(error, "read"):
            response_body = error.read().decode("utf-8", errors="replace")

        print(f"Agent phone alert failed: {error}")
        if response_body:
            print(f"Twilio response: {response_body}")
        return False
