#!/usr/bin/env python3
import smtplib
import ssl

# Configuration
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465  # SSL port
SMTP_USER = "mohammedzayaana@gmail.com"
SMTP_PASSWORD = input("Enter your App Password (16 chars): ")

try:
    # Create SSL connection
    context = ssl.create_default_context()
    server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10, context=context)
    
    # Say hello
    server.ehlo()
    print("✓ Connected to Gmail SSL SMTP")
    
    # Login
    server.login(SMTP_USER, SMTP_PASSWORD)
    print("✓ Authenticated successfully!")
    
    # Send test email
    test_msg = """Subject: Test Email

This is a test from port 465!"""
    server.sendmail(SMTP_USER, SMTP_USER, test_msg.encode('utf-8'))
    print("✓ Test email sent!")
    
    server.quit()
    print("\n✅ SUCCESS! Port 465 works perfectly.")
    
except Exception as e:
    print(f"\n❌ Error: {e}")