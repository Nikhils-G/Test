const express = require('express');
const axios = require('axios');
const app = express();

// Route for displaying network status and anomaly detection
app.get('/', async (req, res) => {
    try {
        // Request prediction from Flask backend
        const predictionResponse = await axios.get('http://127.0.0.1:5000/predict');
        
        // Request anomaly detection result from Flask backend
        const anomalyResponse = await axios.get('http://127.0.0.1:5000/anomaly');

        // Prepare the HTML response
        let html = `<h1>Network Status: ${predictionResponse.data.prediction}</h1>`;
        html += `<h2>Anomaly Detected: ${anomalyResponse.data.anomaly_detected ? 'Yes' : 'No'}</h2>`;

        // If an anomaly is detected, trigger the alert
        if (anomalyResponse.data.anomaly_detected) {
            try {
                const alertResponse = await axios.get('http://127.0.0.1:5000/alert');
                html += `<p>${alertResponse.data.alert}</p>`;
            } catch (alertError) {
                console.error('Error occurred while sending alert:', alertError.message || alertError);
                html += `<p>Failed to send alert: ${alertError.message || alertError}</p>`;
            }
        }

        res.send(html);
    } catch (error) {
        console.error('Error occurred while fetching data:', error.message || error);
        res.status(500).send('Error occurred while fetching data');
    }
});

// Start the frontend server on port 3000
app.listen(3000, () => {
    console.log('Frontend is running on http://localhost:3000');
});
