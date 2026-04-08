import requests

# Exemple de requête normale
normal_data = {
    'timestamp': '2023-10-26T08:00:00',
    'ip_address': '192.168.1.10',
    'request_method': 'GET',
    'request_path': '/products',
    'status_code': 200,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
}

# Exemple de requête malveillante
malicious_data = {
    'timestamp': '2023-10-26T08:01:00',
    'ip_address': '10.0.0.5',
    'request_method': 'GET',
    'request_path': '/admin/users.php?id=1%20UNION%20SELECT%20null,null,null,version()--',
    'status_code': 200,
    'user_agent': 'sqlmap/1.6.10 (http://sqlmap.org)'
}

for label, data in [('Normal', normal_data), ('Malicious', malicious_data)]:
    response = requests.post('http://127.0.0.1:5000/predict', json=data)
    print(f"{label} request prediction:", response.json())
