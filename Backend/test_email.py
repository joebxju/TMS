from app2 import send_async_email

result = send_async_email.delay(
    subject="Test Email",
    body="This is a test email from the system",
    recipient_email="siem4mini@gmail.com"
)
print(f"Task ID: {result.id}")