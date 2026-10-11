const predictionForm = document.getElementById("predictionForm");
const analyzeButton = document.getElementById("analyzeButton");

const resultBox = document.getElementById("resultBox");
const resultTitle = document.getElementById("resultTitle");
const resultMessage = document.getElementById("resultMessage");
const resultIcon = document.getElementById("resultIcon");

const attackScore = document.getElementById("attackScore");
const scoreBar = document.getElementById("scoreBar");
const errorBox = document.getElementById("errorBox");


function getFormData() {
    return {
        protocol_type: document.getElementById("protocol_type").value,

        encryption_used:
            document.getElementById("encryption_used").value,

        browser_type:
            document.getElementById("browser_type").value,

        network_packet_size:
            Number(document.getElementById("network_packet_size").value),

        login_attempts:
            Number(document.getElementById("login_attempts").value),

        session_duration:
            Number(document.getElementById("session_duration").value),

        ip_reputation_score:
            Number(document.getElementById("ip_reputation_score").value),

        failed_logins:
            Number(document.getElementById("failed_logins").value),

        unusual_time_access:
            Number(document.getElementById("unusual_time_access").value)
    };
}


function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
}


function hideMessages() {
    errorBox.hidden = true;
    resultBox.hidden = true;

    errorBox.textContent = "";
}


function displayResult(data) {
    resultBox.hidden = false;

    resultBox.classList.remove("normal", "attack");

    const isAttack = Number(data.prediction) === 1;

    if (isAttack) {
        resultBox.classList.add("attack");

        resultTitle.textContent = "Potential Attack Detected";
        resultIcon.textContent = "!";
        resultMessage.textContent =
            "The model classified this session as a potential attack. " +
            "Investigate the activity before taking action.";
    } else {
        resultBox.classList.add("normal");

        resultTitle.textContent = "Normal Session";
        resultIcon.textContent = "✓";
        resultMessage.textContent =
            "The model classified this session as normal. " +
            "This does not guarantee that the session is safe.";
    }

    if (
        data.attack_score !== null &&
        data.attack_score !== undefined &&
        Number.isFinite(Number(data.attack_score))
    ) {
        const score = Math.max(
            0,
            Math.min(100, Number(data.attack_score))
        );

        attackScore.textContent = `${score.toFixed(2)}%`;
        scoreBar.style.width = `${score}%`;
    } else {
        attackScore.textContent = "Unavailable";
        scoreBar.style.width = "0%";
    }

    resultBox.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}


predictionForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    hideMessages();

    if (!predictionForm.reportValidity()) {
        return;
    }

    const formData = getFormData();

    // Validate numeric inputs
    const numericFields = [
        "network_packet_size",
        "login_attempts",
        "session_duration",
        "ip_reputation_score",
        "failed_logins",
        "unusual_time_access"
    ];

    for (const field of numericFields) {
        if (!Number.isFinite(formData[field])) {
            showError(`Please enter a valid number for ${field}.`);
            return;
        }
    }

    if (
        formData.ip_reputation_score < 0 ||
        formData.ip_reputation_score > 100
    ) {
        showError("IP reputation score must be between 0 and 100.");
        return;
    }

    // Loading state
    analyzeButton.disabled = true;
    analyzeButton.querySelector("span:first-child").textContent =
        "Analyzing...";

    try {
        const response = await fetch("/predict", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(formData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || "Unable to analyze the session."
            );
        }

        displayResult(data);

    } catch (error) {
        showError(
            error.message ||
            "Could not connect to the server. Please try again."
        );

    } finally {
        analyzeButton.disabled = false;

        analyzeButton.querySelector("span:first-child").textContent =
            "Analyze Session";
    }
});


// Reset result when the user resets the form
predictionForm.addEventListener("reset", function () {
    hideMessages();

    resultBox.classList.remove("normal", "attack");
    attackScore.textContent = "--";
    scoreBar.style.width = "0%";
});
