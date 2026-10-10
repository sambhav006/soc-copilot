# Maps the DFIR detector's class labels to MITRE ATT&CK techniques.
# "Normal Traffic" is intentionally absent: it never produces an alert.
# "query" is a richer description used for semantic search.
ATTACK_MAP = {
    "Port Scanning": {
        "techniques": ["T1046"],
        "query": "network service discovery scanning remote hosts for open ports and services",
    },
    "DDoS": {
        "techniques": ["T1498"],
        "query": "network denial of service flooding target with traffic from many sources",
    },
    "DoS": {
        "techniques": ["T1499", "T1498"],
        "query": "denial of service exhausting server resources with high volume requests",
    },
    "Brute Force": {
        "techniques": ["T1110"],
        "query": "brute force password guessing against FTP or SSH login",
    },
    "Web Attacks": {
        "techniques": ["T1190"],
        "query": "exploit public-facing web application SQL injection cross-site scripting",
    },
    "Bots": {
        "techniques": ["T1071"],
        "query": "botnet command and control communication over application layer protocols",
    },
}