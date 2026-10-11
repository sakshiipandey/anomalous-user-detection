from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import math

app = Flask(__name__)

# Load the trained model and feature names
model = joblib.load("models/xgboost_model.pkl")
model_features = joblib.load("models/model_features.pkl")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()

        if not isinstance(data, dict):
            return jsonify({"error": "Invalid input data"}), 400

        # Numeric features used during model training
        numeric_features = [
            "network_packet_size",
            "login_attempts",
            "session_duration",
            "ip_reputation_score",
            "failed_logins",
            "unusual_time_access"
        ]

        # Categorical features and their allowed values
        categorical_features = {
            "protocol_type": ["TCP", "UDP", "ICMP"],
            "encryption_used": ["AES", "DES", "Unknown"],
            "browser_type": [
                "Chrome", "Firefox", "Safari", "Edge", "Unknown"
            ]
        }

        # Validate numeric inputs
        numeric_data = {}

        for feature in numeric_features:
            if feature not in data:
                return jsonify({
                    "error": f"Missing field: {feature}"
                }), 400

            value = float(data[feature])

            if not math.isfinite(value):
                return jsonify({
                    "error": f"{feature} must be a finite number"
                }), 400

            numeric_data[feature] = value

        # Validate categorical inputs
        for feature, allowed_values in categorical_features.items():
            if data.get(feature) not in allowed_values:
                return jsonify({
                    "error": f"Invalid value for {feature}"
                }), 400

        # Create input with the exact training feature order
        input_data = pd.DataFrame(
            0,
            index=[0],
            columns=model_features
        )

        # Fill numerical values
        for feature, value in numeric_data.items():
            if feature not in input_data.columns:
                return jsonify({
                    "error": f"Model feature not found: {feature}"
                }), 500

            input_data.loc[0, feature] = value

        # One-hot encode categorical values
        for feature in categorical_features:
            value = data[feature]
            encoded_column = f"{feature}_{value}"

            if encoded_column in input_data.columns:
                input_data.loc[0, encoded_column] = 1

        # Predict
        prediction = int(model.predict(input_data)[0])

        attack_score = None

        if hasattr(model, "predict_proba"):
            attack_score = float(
                model.predict_proba(input_data)[0][1]
            ) * 100

        result = (
            "Potential Attack Detected"
            if prediction == 1
            else "Normal Session"
        )

        return jsonify({
            "prediction": prediction,
            "attack_score": (
                round(attack_score, 2)
                if attack_score is not None
                else None
            ),
            "result": result
        })

    except (TypeError, ValueError):
        return jsonify({
            "error": "Please provide valid numeric values."
        }), 400

    except Exception:
        app.logger.exception("Prediction failed")

        return jsonify({
            "error": "Prediction failed. Check the server terminal."
        }), 500


if __name__ == "__main__":
    app.run(debug=True)