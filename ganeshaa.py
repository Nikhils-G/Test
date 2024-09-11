import pyshark
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score
import joblib
from flask import Flask, jsonify
from flask_cors import CORS
from twilio.rest import Client

# 1. Data Preprocessing and Feature Extraction
def extract_features(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    data = []

    for packet in capture:
        try:
            packet_time = float(packet.sniff_time.timestamp())
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer
            packet_size = int(packet.length)
            data.append([packet_time, src_ip, dst_ip, protocol, packet_size])
        except AttributeError:
            continue

    columns = ['Time', 'Source IP', 'Destination IP', 'Protocol', 'Packet Size']
    df = pd.DataFrame(data, columns=columns)

    # Drop rows with missing data (if any)
    df = df.dropna(subset=['Packet Size', 'Protocol'])

    # Calculate packet rate as the mean size of packets per source IP
    df['Packet Rate'] = df.groupby(['Source IP'])['Packet Size'].transform('mean')

    return df

# 2. Machine Learning Model
def train_model(df):
    # Prepare features and target variable
    X = df[['Packet Size', 'Packet Rate']]
    y = df['Protocol'].apply(lambda x: 1 if x == 'TCP' else 0)

    # Check for any missing data
    X = X.dropna()
    y = y[X.index]

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy * 100:.2f}%")

    return model, X_train, y_train

# 3. Model Optimization
def optimize_model(model, X_train, y_train):
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [10, 20, 30],
        'min_samples_split': [2, 5, 10]
    }

    grid_search = GridSearchCV(estimator=model, param_grid=param_grid, cv=3, n_jobs=-1, verbose=2)
    grid_search.fit(X_train, y_train)

    best_model = grid_search.best_estimator_
    joblib.dump(best_model, 'optimized_network_model.pkl')
    return best_model

# 4. Anomaly Detection
def train_anomaly_detector(X_train):
    anomaly_model = IsolationForest(contamination=0.01)
    anomaly_model.fit(X_train)
    joblib.dump(anomaly_model, 'anomaly_model.pkl')
    return anomaly_model

# Flask API
app = Flask(__name__)
CORS(app)

# Load pre-trained models
try:
    model = joblib.load('optimized_network_model.pkl')
    anomaly_model = joblib.load('anomaly_model.pkl')
except FileNotFoundError:
    print("Model files not found. Make sure 'optimized_network_model.pkl' and 'anomaly_model.pkl' exist.")

# 1. Prediction Endpoint
@app.route('/predict', methods=['GET'])
def predict():
    try:
        # Create a DataFrame with proper feature names for the model
        input_data = pd.DataFrame([[1500, 100]], columns=["Packet Size", "Packet Rate"])
        prediction = model.predict(input_data)
        return jsonify({"prediction": int(prediction[0])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 2. Anomaly Detection Endpoint
@app.route('/anomaly', methods=['GET'])
def anomaly():
    try:
        # Create a DataFrame with proper feature names for the anomaly detection model
        input_data = pd.DataFrame([[1500, 100]], columns=["Packet Size", "Packet Rate"])
        is_anomaly = anomaly_model.predict(input_data)
        
        # Convert the NumPy bool_ to a native Python bool
        anomaly_detected = bool(is_anomaly[0] == -1)
        return jsonify({"anomaly_detected": anomaly_detected})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 3. Alerting System
@app.route('/alert', methods=['GET'])
def send_alert():
    try:
        # Twilio credentials
        account_sid = 'AC86e26e1703c5859bdec8a92762b'
        auth_token = '5c7e4bc2e1c65ae5dcaf553cf0200cd9'
        twilio_phone_number = '+12088776142'  # Your Twilio phone number
        
        # Create a Twilio client
        client = Client(account_sid, auth_token)
        
        # Send the alert message
        message = client.messages.create(
            to="+91739628627",  # Replace with the actual recipient phone number
            from_=twilio_phone_number,
            body="Alert: Anomaly detected in the network."
        )
        
        return jsonify({"alert": "Alert sent successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 4. Root Route
@app.route('/')
def home():
    return "<h1>Welcome to the Network Monitoring API</h1><p>Available Endpoints: /predict, /anomaly, /alert</p>"

if __name__ == '__main__':
    # Ensure models are trained and saved
    pcap_file = "C:/Users/Nikhil Sukthe/Downloads/5g6g/fuzz-2007-04-25-5694.pcap"
    df = extract_features(pcap_file)
    model, X_train, y_train = train_model(df)
    best_model = optimize_model(model, X_train, y_train)
    train_anomaly_detector(X_train)

    # Load the trained models
    model = joblib.load('optimized_network_model.pkl')
    anomaly_model = joblib.load('anomaly_model.pkl')

    app.run(debug=True)
