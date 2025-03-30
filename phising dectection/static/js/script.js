document.addEventListener('DOMContentLoaded', function() {
    const emailForm = document.getElementById('email-form');
    const loader = document.getElementById('loader');
    const resultCard = document.getElementById('result-card');
    const resultHeader = document.getElementById('result-header');
    const resultTitle = document.getElementById('result-title');
    const resultSummary = document.getElementById('result-summary');
    const probabilityBar = document.getElementById('probability-bar');
    const riskLevel = document.getElementById('risk-level');
    const featureGrid = document.getElementById('feature-grid');

    emailForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Get form data
        const subject = document.getElementById('subject').value;
        const body = document.getElementById('body').value;
        
        // Show loader
        loader.style.display = 'block';
        resultCard.style.display = 'none';
        
        // Send data to API
        fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                subject: subject,
                body: body
            }),
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Hide loader
            loader.style.display = 'none';
            
            // Display results
            displayResults(data);
        })
        .catch(error => {
            console.error('Error:', error);
            loader.style.display = 'none';
            alert('An error occurred while analyzing the email. Please try again.');
        });
    });

    function displayResults(data) {
        // Show result card
        resultCard.style.display = 'block';
        
        // Update header based on result
        if (data.is_phishing) {
            resultHeader.className = 'result-header phishing';
            resultHeader.innerHTML = '<i class="fas fa-exclamation-triangle"></i><h2>Phishing Detected!</h2>';
            resultSummary.textContent = 'This email appears to be a phishing attempt. Be cautious and do not click on any links or provide any personal information.';
        } else {
            resultHeader.className = 'result-header legitimate';
            resultHeader.innerHTML = '<i class="fas fa-check-circle"></i><h2>Email Appears Legitimate</h2>';
            resultSummary.textContent = 'Our analysis suggests this is likely a legitimate email. However, always remain vigilant.';
        }
        
        // Update probability bar
        const probability = data.probability * 100;
        probabilityBar.style.width = `${probability}%`;
        probabilityBar.textContent = `${probability.toFixed(1)}%`;
        
        // Set risk level class
        if (probability > 75) {
            probabilityBar.className = 'progress-bar high-risk';
            riskLevel.textContent = 'High Risk';
            riskLevel.style.color = '#e63946';
        } else if (probability > 40) {
            probabilityBar.className = 'progress-bar medium-risk';
            riskLevel.textContent = 'Medium Risk';
            riskLevel.style.color = '#ffb703';
        } else {
            probabilityBar.className = 'progress-bar low-risk';
            riskLevel.textContent = 'Low Risk';
            riskLevel.style.color = '#52b788';
        }
        
        // Display features
        featureGrid.innerHTML = '';
        
        // Create feature items
        const features = [
            { name: 'URLs Detected', value: data.features.url_count },
            { name: 'Suspicious URL Ratio', value: (data.features.suspicious_url_ratio * 100).toFixed(1) + '%' },
            { name: 'Urgent Language', value: data.features.urgent_word_count },
            { name: 'Misspelled Domains', value: data.features.misspelled_domain_count },
            { name: 'Sensitive Requests', value: data.features.sensitive_info_requests }
        ];
        
        features.forEach(feature => {
            const featureItem = document.createElement('div');
            featureItem.className = 'feature-item';
            featureItem.innerHTML = `
                <h4>${feature.name}</h4>
                <p>${feature.value}</p>
            `;
            featureGrid.appendChild(featureItem);
        });
        
        // Scroll to results
        resultCard.scrollIntoView({ behavior: 'smooth' });
    }
});