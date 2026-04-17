# NetGuard — Network Packet Threat Detector UI
## Complete Setup Guide (Every Step Explained)

---

## YOUR PROJECT FOLDER STRUCTURE

```
netguard/
│
├── app.py              ← Flask backend (Python web server)
├── model.pkl           ← Your trained model from Colab (you add this)
├── requirements.txt    ← Python packages needed
│
└── templates/
    └── index.html      ← The full UI (dashboard)
```

---

## STEP 1 — SAVE YOUR MODEL IN GOOGLE COLAB

In your Colab notebook, after training, run this cell:

```python
import pickle

# Save both the model AND the label encoder
# (label encoder converts numbers back to "Normal", "SYN Flood" etc.)
model_data = {
    "model":  rf,        # use rf, lr, or svm — whichever you want
    "labels": le_labels  # the LabelEncoder from your notebook
}

pickle.dump(model_data, open("model.pkl", "wb"))

# Download model.pkl to your computer
from google.colab import files
files.download("model.pkl")
```

⚠️ IMPORTANT — If your Colab also used PCA (it did!), save the PCA too:

```python
model_data = {
    "model":   rf,
    "labels":  le_labels,
    "scaler":  scaler,   # the StandardScaler
    "pca":     pca       # the PCA object
}
pickle.dump(model_data, open("model.pkl", "wb"))
```

Then in app.py, uncomment these lines inside the /predict route:

```python
scaler = model_data["scaler"]
pca    = model_data["pca"]
X      = scaler.transform(X)
X      = pca.transform(X)
```

---

## STEP 2 — INSTALL PYTHON PACKAGES

Open your Terminal (Mac/Linux) or Command Prompt (Windows).
Go to your netguard folder:

```bash
cd netguard
pip install -r requirements.txt
```

This installs:
- flask      → turns Python into a web server
- numpy      → handles number arrays for the model
- scikit-learn → needed to load the pickle model

---

## STEP 3 — PLACE model.pkl IN THE FOLDER

Copy the model.pkl you downloaded from Colab and paste it into
the netguard/ folder (same level as app.py).

```
netguard/
├── app.py
├── model.pkl    ← put it here
├── requirements.txt
└── templates/
    └── index.html
```

---

## STEP 4 — RUN THE FLASK SERVER

In your terminal, inside the netguard/ folder:

```bash
python app.py
```

You will see:
```
✅ model.pkl loaded successfully
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

---

## STEP 5 — OPEN YOUR BROWSER

Go to:   http://localhost:5000

You will see the full dashboard with:
✅ Your model loaded (green badge in top right)
✅ All 14 packet input fields
✅ Model selector (LR / SVM / Random Forest)
✅ Analyze Packet button
✅ Live Packet Feed
✅ Detection Breakdown bar chart
✅ Threat Level stats

---

## HOW IT WORKS (End to End)

```
[Browser / index.html]
    User fills in packet values
    Clicks "Analyze Packet"
    JavaScript sends POST request to /predict
         ↓
[Flask / app.py]
    /predict receives the JSON
    Builds numpy feature array
    Runs model.predict()
    Returns { label, confidence, is_attack }
         ↓
[Browser / index.html]
    JavaScript receives the result
    Shows result box (green = normal, red = attack)
    Adds entry to live feed
    Updates bar chart and stat cards
```

---

## SIMULATE BUTTONS

- "Normal Traffic" button → fills realistic normal values → auto-analyzes
- "DDoS Attack" button   → fills attack pattern values   → auto-analyzes

These let you test the UI even before connecting the real model.

---

## TROUBLESHOOTING

| Problem | Fix |
|---------|-----|
| "model.pkl not found" | Place model.pkl in the netguard/ folder |
| Port 5000 already in use | Change port in app.py: app.run(port=5001) |
| Prediction is always wrong | Make sure scaler + PCA are saved and applied in /predict |
| ModuleNotFoundError | Run: pip install -r requirements.txt |

---

## FILES EXPLAINED

| File | What it does |
|------|-------------|
| app.py | Flask server. Loads model. Has /predict route. |
| templates/index.html | The full dashboard UI (HTML + CSS + JS in one file) |
| model.pkl | Your trained model from Colab (you must add this) |
| requirements.txt | Python packages list |
