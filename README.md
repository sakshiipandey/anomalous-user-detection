# 🛡️ Anomalous User Detection

### Machine Learning | Cybersecurity | XGBoost | Streamlit

Anomalous User Detection is a machine learning project designed to identify
suspicious user activity and detect potential cyberattacks using network
session data.

The project uses an XGBoost classifier and provides an interactive Streamlit
dashboard where users can enter session details and receive predictions.

---

## 🚀 Features

- 🔍 Detects potentially suspicious network sessions
- 🤖 Machine learning model powered by XGBoost
- 📊 Interactive Streamlit dashboard
- 🌐 Flask-based web interface
- 🔐 Analyzes network and login-related features
- 📈 Displays predictions and model attack scores
- ⚡ Real-time predictions for user-provided session data

---

## 🧠 Machine Learning Workflow

1. Load and explore the cybersecurity dataset.
2. Handle missing values.
3. Remove unnecessary identifiers.
4. Encode categorical variables.
5. Split data into training and testing sets.
6. Train and evaluate machine learning models.
7. Select the XGBoost classifier.
8. Save the trained model and feature names.
9. Use the saved model to predict potential attacks.

---

## 🛠️ Tech Stack

- **Language:** Python
- **Machine Learning:** XGBoost, Scikit-learn
- **Data Processing:** Pandas, NumPy
- **Web Application:** Render, Flask
- **Model Serialization:** Joblib
- **Development:** Jupyter Notebook
- **Version Control:** Git and GitHub

---

## 📂 Project Structure

```text
anomalous-user-detection/
│
├── models/
│   ├── model_features.pkl
│   └── xgboost_model.pkl
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── templates/
│   └── index.html
│
├── anomaly_detection.ipynb
├── app.py
├── requirements.txt
└── README.md
