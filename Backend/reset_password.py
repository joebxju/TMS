from supabase import create_client

SUPABASE_URL = "https://andeokpadwnohnryzejw.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFuZGVva3BhZHdub2hucnl6ZWp3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0MDc2MjkyOCwiZXhwIjoyMDU2MzM4OTI4fQ.ucONbFaVG9ki6R4c2nl3d6u4GtWoD4T3awPoRENdjW0"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Send password reset email
email = "jestinkonami3@gmail.com"
supabase.auth.reset_password_for_email(email)

print("Password reset email sent!")
