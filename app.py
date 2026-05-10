from flask import Flask, render_template, request
import pickle
import numpy as np
from urllib.parse import urlparse
from dataset import TRUSTED
from feature_extractor import extract_features


# Load trained model generated from phishing_urls.csv
model = pickle.load(open("model/phishing_model.pkl", "rb"))

app = Flask(__name__)

PREDICTION_LABELS = {
    0: "Phishing Website",
    1: "Safe Website",
}


def normalize_domain(value):
    parsed = urlparse(value if "://" in value else f"https://{value}")
    domain = parsed.netloc.lower().split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


TRUSTED_DOMAINS = {normalize_domain(site) for site in TRUSTED}


def is_trusted_url(url):
    domain = normalize_domain(url)
    return any(domain == trusted or domain.endswith(f".{trusted}") for trusted in TRUSTED_DOMAINS)


@app.route("/", methods=["GET", "POST"])
def home():
    prediction = ""

    if request.method == "POST":
        url = request.form["url"]
        features = np.array(extract_features(url)).reshape(1, -1)

        result = int(model.predict(features)[0])
        probability = model.predict_proba(features)[0]

        phishing_index = list(model.classes_).index(0)
        phishing_risk = round(float(probability[phishing_index]) * 100, 2)

        label = PREDICTION_LABELS.get(result, "Unknown Website")
        if is_trusted_url(url):
            label = "Safe Website"
            phishing_risk = 0

        prediction = f"{label} (Risk: {phishing_risk}%)"

    return render_template("index.html", prediction=prediction)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
