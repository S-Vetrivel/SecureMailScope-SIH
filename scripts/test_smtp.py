import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg.set_content("This is a test email for SecureMailScope Live Sensor.")
msg['Subject'] = "SecureMailScope Live Test"
msg['From'] = "test@example.com"
msg['To'] = "recipient@example.com"

# Connect to a public test SMTP server or just an invalid one to trigger packets
try:
    print("Connecting to SMTP server...")
    s = smtplib.SMTP('smtp.mailgun.org', 587, timeout=5)
    s.ehlo()
    s.starttls()
    s.ehlo()
    print("Sent EHLO, connection successful.")
    s.quit()
except Exception as e:
    print(f"Finished: {e}")
