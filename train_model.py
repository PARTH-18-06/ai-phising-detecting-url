import csv
import os
import pickle

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

from feature_extractor import FEATURE_NAMES, extract_features, features_from_row


SAFE_URLS = [
    "https://www.wikipedia.org/",
    "https://www.google.com/",
    "https://github.com/",
    "https://stackoverflow.com/questions",
    "https://www.microsoft.com/en-us/",
    "https://www.apple.com/shop",
    "https://www.amazon.com/products",
    "https://www.linkedin.com/login",
    "https://www.paypal.com/signin",
    "https://www.coursera.org/learn/python",
    "https://www.nasa.gov/news/",
    "https://www.bbc.com/news",
]

PHISHING_URLS = [
    "https://demo-store.fake/products",
    "http://demo-store.fake/products",
    "https://paypal-security.fake/login",
    "https://account-verify.fake/update",
    "http://secure-login-update.xyz/paypal",
    "https://bank-account-confirm.top/login",
    "http://192.168.1.40/verify/account",
    "https://free-prize-wallet.click/claim",
    "https://support-paypal-login.work/signin",
    "https://github.com.secure-update.fake/session",
    "https://wikipedia.org.account-check.fake/login",
    "http://login.paypal.com.fake/secure",
    "https://verify-account-billing.link/password",
    "https://www.amazon.com.fake/products",
    "https://google.com.security-review.xyz/login",
    "https://account%2Dverify.fake/login",
    "https://fake-wikipedia.org/",
    "https://wikipedia-login.org/account",
    "https://wikipedia-secure.org/verify",
    "https://microsoft-support-login.com/update",
    "https://appleid-verify-support.com/signin",
    "https://paypal-billing-confirm.com/account",
    "https://github-security-alert.com/session",
    "https://amazon-order-review.com/login",
    "https://google-account-verify.com/password",
    "https://linkedin-security-check.com/signin",
]


def load_csv_dataset(path):
    x_values = []
    y_values = []
    sample_weights = []

    with open(path, newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            x_values.append(features_from_row(row))
            y_values.append(int(row["target"]))
            sample_weights.append(1.0)

    return x_values, y_values, sample_weights


def add_url_examples(x_values, y_values, sample_weights, urls, target, weight):
    for url in urls:
        x_values.append(extract_features(url))
        y_values.append(target)
        sample_weights.append(weight)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(script_dir, "phishing_urls.csv")

    x_values, y_values, sample_weights = load_csv_dataset(dataset_path)

    add_url_examples(x_values, y_values, sample_weights, SAFE_URLS, target=1, weight=8.0)
    add_url_examples(x_values, y_values, sample_weights, PHISHING_URLS, target=0, weight=12.0)

    x_train, x_test, y_train, y_test, w_train, _ = train_test_split(
        x_values,
        y_values,
        sample_weights,
        test_size=0.2,
        random_state=42,
        stratify=y_values,
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(x_train, y_train, sample_weight=w_train)

    y_pred = model.predict(x_test)
    print("Validation accuracy:", round(accuracy_score(y_test, y_pred) * 100, 2), "%")

    model.fit(x_values, y_values, sample_weight=sample_weights)

    model_dir = os.path.join(script_dir, "model")
    os.makedirs(model_dir, exist_ok=True)

    model_path = os.path.join(model_dir, "phishing_model.pkl")
    with open(model_path, "wb") as model_file:
        pickle.dump(model, model_file)

    print("Feature count:", len(FEATURE_NAMES))
    print("Model saved at:", model_path)
    print("Model trained successfully!")


if __name__ == "__main__":
    main()
