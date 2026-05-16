# ShieldScan

AI phishing URL detection app with user profiles, agent review, alert-zone approvals, and SMS/WhatsApp notification support.

## Project Structure

```text
ai-phising-detecting-url/
├── app.py
├── requirements.txt
├── .env.example
├── README.md
├── data/
│   ├── Dataset.csv
│   └── phishing_urls.csv
├── local/
│   ├── launch_local.py
│   └── launch_server.ps1
├── model/
│   └── phishing_model.pkl
├── scripts/
│   ├── check_dataset.py
│   ├── download_dataset.py
│   └── train_model.py
├── services/
│   ├── dataset.py
│   ├── feature_extractor.py
│   ├── notifier.py
│   └── scan_store.py
└── templates/
    ├── agent_login.html
    ├── auth.html
    ├── index.html
    ├── monitor.html
    └── profile.html
```

## Local Launch

```powershell
python local\launch_local.py
```

Then open:

```text
http://127.0.0.1:5000/
```

## Training

```powershell
python scripts\train_model.py
```

The script reads `data/phishing_urls.csv` and writes the trained model to `model/phishing_model.pkl`.

## Local-Only Files

These are intentionally ignored and should not be pushed:

```text
.env
.venv/
__pycache__/
data/*.db
server*.log
```
