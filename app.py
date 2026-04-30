from flask import Flask, render_template, request
import pickle
import numpy as np
from urllib.parse import urlparse
from dataset import TRUSTED

# Load trained model
model = pickle.load(open("model/phishing_model.pkl", "rb"))

app = Flask(__name__)

# Function to extract features from URL
def extract_features(url):

    features = []

    features.append(len(url))                          # url_length
    features.append(1 if url.startswith("http") else 0) # valid_url
    features.append(url.count("@"))                    # at_symbol
    features.append(0)                                 # sensitive_words_count
    features.append(url.count("/"))                    # path_length
    features.append(1 if "https" in url else 0)        # isHttps
    features.append(url.count("."))                    # nb_dots
    features.append(url.count("-"))                    # nb_hyphens
    features.append(url.count("&"))                    # nb_and
    features.append(url.count("|"))                    # nb_or
    features.append(url.count("www"))                  # nb_www
    features.append(url.count(".com"))                 # nb_com
    features.append(url.count("_"))                    # nb_underscore

    return features


@app.route("/", methods=["GET", "POST"])
def home():

    prediction = ""

    if request.method == "POST":

        url = request.form["url"]

        # 🔒 Extract domain for trusted check
        domain = urlparse(url).netloc

        trusted = TRUSTED
       
        if any(site in domain for site in trusted):
            prediction = "✅ Safe Website"

        else:
            # Extract features
            features = extract_features(url)
            features = np.array(features).reshape(1, -1)
            # Model prediction
            result = model.predict(features)

            # Probability (better accuracy)
            prob = model.predict_proba(features)
            phishing_prob = prob[0][1]

           # if phishing_prob > 0.6:
            if any(site not in domain for site in trusted):
                prediction = f"⚠️ Phishing Website (Risk: {round(phishing_prob*100,2)}%)"
            else:
                prediction = f"✅ Safe Website (Risk: {round(phishing_prob*100,2)}%)"

    return render_template("index.html", prediction=prediction)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)