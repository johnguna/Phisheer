# Raspberry Pi 5 AI-Based Multilingual Cybersecurity System

Educational starter project combining network intrusion alerts, URL checks, file scanning, a baseline message classifier, a Flask dashboard, and a safe router-blocking placeholder.

## Safety and limitations
- This is a prototype, not a complete commercial security product or a guarantee against all threats.
- WhatsApp/Instagram private messages are not accessed or decrypted. A future Android companion can submit notification previews only with user permission.
- Email must use authorized OAuth access. Never store account passwords in source code.
- SPAN/port mirroring is passive: it copies traffic to the Pi and cannot block the original traffic.
- HTTPS and end-to-end encryption generally hide payload contents; network monitoring can inspect alerts and metadata.
- Router blocking is disabled and dry-run by default. Exact implementation depends on router model, hardware revision and firmware.
- Test only on networks and devices you own or are authorized to monitor.

## Structure
```text
app.py
config.yaml
core/              alert storage and conservative policy
detection/         Suricata, URL, file and message modules
firewall/          safe router adapter placeholder
dashboard/         Flask dashboard
scripts/           demo model training
data/              tiny sample dataset
tests/             unit tests
```

## Install on Raspberry Pi OS 64-bit
```bash
sudo apt update
sudo apt install -y git python3-venv python3-pip clamav suricata
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-ml.txt
cp .env.example .env
```
Edit `config.yaml` to match your Suricata EVE path. Run:
```bash
python app.py
```
Open `http://127.0.0.1:5000` on the Pi. The Flask development server is for local testing only; do not expose it to the internet.

## Suricata
Common EVE path: `/var/log/suricata/eve.json`. Confirm on your installation:
```bash
sudo tail -f /var/log/suricata/eve.json
```
For SPAN monitoring, use a dedicated monitor interface without an IP/default gateway and verify copied traffic with `tcpdump`. Keep the Pi's management interface separate.

## Demo message model
```bash
python scripts/train_message_model.py
```
The included dataset is tiny and illustrative only. It is not suitable for real-world classification. Tamil/English and code-mixed language support still needs a representative, properly licensed dataset and an appropriate multilingual model.

## Firewall
The included adapter never sends router commands. Before implementing real blocking, confirm the exact router model and firmware, back up its configuration, protect management IPs with an allowlists, use temporary blocks with expiry, and test in a lab. Start with human approval.

## Tests
```bash
python -m unittest discover -s tests -v
```

## Suggested next stages
1. Run dashboard and local URL/file/message demos.
2. Connect Suricata EVE JSON.
3. Train/evaluate with a representative dataset.
4. Add an Android notification-preview companion with explicit consent.
5. Add OAuth email integration.
6. Implement a router-specific firewall adapter only after verifying the device.

Choose a license before publishing and comply with all third-party code, model, rules and dataset licenses.
