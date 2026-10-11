import streamlit as st
import pandas as pd
import joblib
import math
from pathlib import Path



st.set_page_config(
    page_title="CyberShield | Anomaly Detection",
    page_icon="🛡️",
    layout="wide"
)




st.markdown("""
<style>
.stApp {
    background-color: #080d19;
    color: #edf4ff;
}

[data-testid="stSidebar"] {
    background-color: #0b1220;
}

h1, h2, h3 {
    color: #edf4ff;
}

.stButton > button {
    background: linear-gradient(90deg, #42a5ff, #36e0dc);
    color: #061321;
    border: none;
    border-radius: 8px;
    font-weight: bold;
    width: 100%;
    min-height: 45px;
}

.stButton > button:hover {
    border: 1px solid #42a5ff;
    color: white;
}

div[data-testid="stMetric"] {
    background-color: #101a2b;
    padding: 18px;
    border: 1px solid #22314a;
    border-radius: 12px;
}

div[data-testid="stForm"] {
    background-color: #101a2b;
    padding: 20px;
    border: 1px solid #22314a;
    border-radius: 12px;
}

</style>
""", unsafe_allow_html=True)


# saved model

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "xgboost_model.pkl"
FEATURES_PATH = BASE_DIR / "models" / "model_features.pkl"


@st.cache_resource
def load_model():
    model = joblib.load(MODEL_PATH)
    features = joblib.load(FEATURES_PATH)
    return model, features


st.title("🛡️ CyberShield")
st.subheader("Anomalous User Detection System")

st.write(
    "Analyze network session details using a trained "
    "XGBoost machine learning model."
)

st.caption("Machine Learning • Cybersecurity • Threat Detection")

st.divider()


#model

try:
    model, model_features = load_model()

except Exception as error:
    st.error(
        "The model could not be loaded. "
        "Check the model files and package versions."
    )
    st.exception(error)
    st.stop()


st.success("Detection model loaded successfully.")

st.divider()


# ---------------- INPUT FORM ----------------

st.header("🔍 Network Session Analysis")

with st.form("prediction_form"):

    col1, col2, col3 = st.columns(3)

    with col1:
        protocol_type = st.selectbox(
            "Protocol Type",
            ["TCP", "UDP", "ICMP"]
        )

        network_packet_size = st.number_input(
            "Network Packet Size",
            min_value=0.0,
            value=512.0
        )

        login_attempts = st.number_input(
            "Login Attempts",
            min_value=0,
            value=3
        )

    with col2:
        encryption_used = st.selectbox(
            "Encryption",
            ["AES", "DES", "Unknown"]
        )

        session_duration = st.number_input(
            "Session Duration",
            min_value=0.0,
            value=120.0
        )

        failed_logins = st.number_input(
            "Failed Logins",
            min_value=0,
            value=2
        )

    with col3:
        browser_type = st.selectbox(
            "Browser Type",
            ["Chrome", "Firefox", "Safari", "Edge", "Unknown"]
        )

        ip_reputation_score = st.number_input(
            "IP Reputation Score",
            min_value=0.0,
            max_value=100.0,
            value=25.0
        )

        unusual_time_access = st.selectbox(
            "Unusual Time Access",
            options=[0, 1],
            format_func=lambda x: "Yes" if x == 1 else "No"
        )

    submitted = st.form_submit_button(
        "Analyze Session →",
        use_container_width=True
    )


# prediction

if submitted:

    try:
        numeric_values = {
            "network_packet_size": network_packet_size,
            "login_attempts": login_attempts,
            "session_duration": session_duration,
            "ip_reputation_score": ip_reputation_score,
            "failed_logins": failed_logins,
            "unusual_time_access": unusual_time_access
        }

        if not all(
            math.isfinite(float(value))
            for value in numeric_values.values()
        ):
            st.error("Please provide valid numeric inputs.")

        else:

            # Create input using the model's training features
            input_data = pd.DataFrame(
                0,
                index=[0],
                columns=model_features
            )

            # Set numeric feature values
            for feature, value in numeric_values.items():

                if feature not in input_data.columns:
                    raise ValueError(
                        f"Missing model feature: {feature}"
                    )

                input_data.loc[0, feature] = value

            # Set categorical one-hot features
            categorical_values = {
                "protocol_type": protocol_type,
                "encryption_used": encryption_used,
                "browser_type": browser_type
            }

            for feature, value in categorical_values.items():

                encoded_column = f"{feature}_{value}"

                if encoded_column in input_data.columns:
                    input_data.loc[0, encoded_column] = 1

            # Prediction
            prediction = int(model.predict(input_data)[0])

            attack_score = None

            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(input_data)[0]

                # Find the probability corresponding to class 1
                classes = list(model.classes_)

                if 1 in classes:
                    attack_score = float(
                        probabilities[classes.index(1)]
                    ) * 100

            st.divider()
            st.header("📊 Analysis Result")

            result_col, score_col = st.columns(2)

            if prediction == 1:

                with result_col:
                    st.error("⚠️ Potential Attack Detected")

                st.warning(
                    "The model classified this session as a potential "
                    "attack. Investigate the activity before taking action."
                )

            else:

                with result_col:
                    st.success("✅ Normal Session")

                st.info(
                    "The model classified this session as normal. "
                    "This does not guarantee that the session is safe."
                )

            with score_col:

                if attack_score is not None:
                    st.metric(
                        "Model Attack Score",
                        f"{attack_score:.2f}%"
                    )

                    st.progress(
                        max(0.0, min(1.0, attack_score / 100))
                    )

                else:
                    st.metric(
                        "Model Attack Score",
                        "Unavailable"
                    )

            st.caption(
                "The attack score is the model's output for the attack "
                "class; it is not necessarily a calibrated real-world "
                "probability. Predictions are not confirmed security "
                "incidents."
            )

    except Exception:
        st.error(
            "Prediction failed. Check the model feature names, "
            "categorical encoding, and installed package versions."
        )
        st.exception(Exception("See the error above."))


#footer

st.divider()

st.caption(
    "CyberShield | Anomalous User Detection | "
    "Python • XGBoost • Streamlit"
)