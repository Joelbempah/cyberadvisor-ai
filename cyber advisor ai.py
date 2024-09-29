import openai  # OpenAI's API to interact with GPT
import requests  # For interacting with other services like VirusTotal
import re  # For URL validation

# Security configuration for API keys
OPENAI_API_KEY = "your_openai_key"
VIRUSTOTAL_API_KEY = "your_virustotal_key"

# Setting up API keys
openai.api_key = OPENAI_API_KEY

# URL Validation function
def is_valid_url(url):
    """Check if the string is a valid URL"""
    regex = re.compile(
        r'^(https?://)?'  # http:// or https://
        r'(\w+(\-\w+)*\.)?(\w+\.)+\w{2,}'  # domain
        r'(/\S*)?'  # optional path
    )
    return re.match(regex, url)

# Categorize the query
def categorize_query(user_input):
    """Categorize user's query to decide next action"""
    if "password" in user_input.lower():
        return "password_check"
    elif "email compromised" in user_input.lower():
        return "phishing_check"
    elif "link" in user_input.lower() or "url" in user_input.lower():
        return "link_check"
    else:
        return "general"

# Password Strength Checker Function
def password_strength_check(password):
    """Evaluate password strength and provide advice"""
    if len(password) < 8:
        return "Your password is too short. Make it at least 8 characters long for better security!"
    elif not any(char.isdigit() for char in password):
        return "Your password needs to include numbers to be stronger."
    elif not any(char.isupper() for char in password):
        return "Including uppercase letters can make your password much harder to guess."
    elif not any(char in "!@#$%^&*()-_=+[]{};:'\"|,.<>/?`~" for char in password):
        return "Try adding special characters like @ or # to make your password stronger!"
    else:
        return "Your password looks good! Remember to avoid using predictable phrases like 'password123'!"

# Phishing Check Function
def phishing_advice(email):
    """Check if an email might be compromised (suggest external service)"""
    if "@" not in email:
        return "Hmm, that doesn't look like an email address. Could you double-check it?"
    else:
        return "You can check if your email has been in a data breach using HaveIBeenPwned.com. Always be wary of suspicious emails asking for sensitive info!"

# Link Safety Check Function
def is_link_safe(url):
    """Check if a given URL is safe using VirusTotal"""
    if not is_valid_url(url):
        return "This doesn't look like a valid URL. Could you check the format?"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
        if response.status_code == 200:
            # Simulate interpreting VirusTotal response
            safety_score = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious")
            if safety_score > 0:
                return "Whoa, this link has been flagged as potentially unsafe. Proceed with caution!"
            else:
                return "Looks like this link is clean, but always be careful where you click!"
        else:
            return "Couldn't verify the safety of this link right now. You might want to try again later."
    except Exception as e:
        return f"Error while checking link safety: {str(e)}"

# General GPT-4 Interaction
def generate_general_advice(user_input):
    """Generate general advice using GPT-4"""
    response = openai.Completion.create(
        engine="gpt-4",  # Assuming GPT-4
        prompt=f"You are a friendly cybersecurity assistant. Answer the following question: {user_input}",
        max_tokens=150
    )
    return response.choices[0].text.strip()

# Handle User Input
def cyberadvisor_query(user_input):
    """Process the user query and generate appropriate responses"""
    query_category = categorize_query(user_input)
    
    if query_category == "password_check":
        return password_strength_check(user_input)
    elif query_category == "phishing_check":
        return phishing_advice(user_input)
    elif query_category == "link_check":
        return is_link_safe(user_input)
    else:
        return generate_general_advice(user_input)

# Main loop for interaction
if __name__ == "__main__":
    print("Hey, I'm your friendly CyberAdvisor AI! How can I help keep you safe today?")
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            print("Stay safe out there! Catch you later!")
            break
        response = cyberadvisor_query(user_input)
        print("CyberAdvisor AI:", response)