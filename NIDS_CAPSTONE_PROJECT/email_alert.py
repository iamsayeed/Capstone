import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(subject, body, to_email):
    """Send an email alert for malicious traffic."""
    from_email = "sendmailscap@gmail.com"  # Replace with your email
    from_password = "Admin@123"        # Replace with your email password

    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()

        print("[EmailAlert] Email sent successfully.")
    except Exception as e:
        print(f"[EmailAlert] Failed to send email: {e}")
