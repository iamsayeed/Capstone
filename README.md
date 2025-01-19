# Capstone
# Network Intrusion Detection System (NIDS)

## Overview
The **Network Intrusion Detection System (NIDS)** is a comprehensive solution for detecting, analyzing, and responding to network threats. It leverages packet analysis, threat intelligence, and customizable detection rules to safeguard network infrastructure.

## Features
- **Packet Analysis**: Monitors network traffic using tools like `tshark`.
- **Intrusion Detection**: Detects potential threats based on predefined rules (`rules.txt`).
- **Firewall Integration**: Blocks malicious traffic automatically.
- **Email Alerts**: Sends alerts for detected intrusions.
- **Web Interface**: Provides a user-friendly interface for monitoring and managing detections.

## Installation
### Prerequisites
- Python 3.8 or above
- SQLite
- Tshark (Wireshark CLI)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/NIDS_Project.git
   cd NIDS_Project
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up the database:
   ```bash
   python db_setup.py
   ```
4. Run the application:
   ```bash
   python app.py
   ```
5. Access the web interface at `http://localhost:5000`.

## Project Structure
```plaintext
nide_project/
├── app.py               # Main application file
├── db_setup.py          # Database setup script
├── detector.py          # Intrusion detection logic
├── email_alert.py       # Email alert module
├── firewall.py          # Firewall rule management
├── intrusions.db        # Database for intrusion data
├── packet.pcap          # Sample packet capture file
├── pcap_analyzer.py     # Packet analysis script
├── rules.txt            # Intrusion detection rules
├── static/              # Static files (CSS, JS, images)
├── templates/           # HTML templates for the web interface
├── threat_intel.py      # Threat intelligence integration
├── sqlite-tools/        # SQLite utilities
└── nide_tshark.py       # Tshark integration script
```

## Usage
1. Start the application.
2. Monitor the dashboard for intrusion alerts.
3. Customize detection rules in `rules.txt` as needed.
4. Review captured packets using `pcap_analyzer.py`.
5. Use `firewall.py` to enforce dynamic blocking rules.

## Contributors
The following individuals have contributed significantly to this project:

1. **Mohammed Sayeed Shirur** - Lead Developer
2. **Vishal G Dhavali** - Database Architect
3. **Aditya Gupta** - Frontend Engineer & Backend Specialist
4. **Ramakrishna** - Threat Intelligence Analyst
5. **Tejas SP** - Information Specialist
6. **Entire Group** - Quality Assurance Engineer


## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit changes: `git commit -m 'Add feature'`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments
- **Wireshark/Tshark**: For packet analysis tools.
- **SQLite**: Lightweight database engine.
- **Open Source Libraries**: Refer to `requirements.txt` for a list of dependencies.

## Contribution
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit changes: `git commit -m 'Add feature'`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

