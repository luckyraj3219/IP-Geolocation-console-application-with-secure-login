import csv
import bcrypt
import re
import requests
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='user_activity.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Read users from CSV file
def read_users():
    users = []
    try:
        with open('regno.csv', mode='r') as file:
            reader = csv.DictReader(file)
            users = [row for row in reader]
    except FileNotFoundError:
        pass
    return users

# Write users back to the CSV file
def write_users(users):
    with open('regno.csv', mode='w', newline='') as file:
        fieldnames = ['email', 'password', 'security_question', 'login_attempts']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(users)

# Function to hash the password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Function to check the hashed password
def check_password(hashed_password, entered_password):
    return bcrypt.checkpw(entered_password.encode(), hashed_password)

# Update login attempts in the CSV
def update_login_attempts(email, users, attempts):
    for user in users:
        if user['email'] == email:
            user['login_attempts'] = str(attempts)
            write_users(users)
            return

# Login function with login attempts tracking
def login():
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    
    users = read_users()
    
    for user in users:
        if 'email' in user and user['email'] == email:
            attempts = int(user.get('login_attempts', 0))
            
            # Check if the user is blocked due to too many failed attempts
            if attempts >= 5:
                print("Your account is blocked due to too many failed login attempts.")
                logging.info(f"Blocked login attempt for {email}.")
                return None
            
            # If password is correct, reset attempts and login successfully
            if check_password(user['password'].encode(), password):
                print("Login successful!")
                user['login_attempts'] = '0'  # Reset the attempts on successful login
                write_users(users)
                logging.info(f"User {email} logged in successfully.")

                # Prompt for IP and fetch geolocation after successful login
                ip_choice = input("Enter an IP address or press enter to use your own: ")
                get_geolocation(ip_choice)
                return user
            else:
                # Increment the login attempt count
                attempts += 1
                update_login_attempts(email, users, attempts)
                remaining_attempts = 5 - attempts
                print(f"Invalid password. You have {remaining_attempts} attempts remaining.")
                logging.warning(f"Failed login attempt for {email}. Remaining attempts: {remaining_attempts}")
                if attempts >= 5:
                    print("Your account is now blocked due to too many failed login attempts.")
                    logging.warning(f"Account {email} blocked due to too many failed attempts.")
                return None
    
    print("User not found.")
    logging.warning(f"Login attempt with non-existent email: {email}.")
    return None

# Function to sign up a user with default login_attempts = 0
def sign_up():
    email = input("Enter your email: ")
    if not validate_email(email):
        print("Invalid email format.")
        logging.warning(f"Invalid email format entered: {email}.")
        return

    password = input("Enter your password: ")
    if not validate_password(password):
        print("Password does not meet criteria.")
        logging.warning(f"Invalid password criteria for email: {email}.")
        return

    security_question = input("What is your school name? ")
    
    hashed_pw = hash_password(password)
    user = {'email': email, 'password': hashed_pw.decode(), 'security_question': security_question, 'login_attempts': '0'}
    
    users = read_users()
    users.append(user)
    write_users(users)
    print("Sign up successful!")
    logging.info(f"New user {email} signed up successfully.")

# Helper functions for email and password validation
def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# Function to get geolocation using IP Geolocation API
def get_geolocation(ip=""):
    api_url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(api_url)
        data = response.json()
        if data['status'] == 'fail':
            print("Invalid IP or no data found.")
            logging.warning(f"Geolocation failed for IP: {ip}.")
        else:
            print(f"Country: {data['country']}")
            print(f"City: {data['city']}")
            print(f"Region: {data['regionName']}")
            print(f"Latitude: {data['lat']}")
            print(f"Longitude: {data['lon']}")
            print(f"Timezone: {data['timezone']}")
            print(f"ISP: {data['isp']}")
            logging.info(f"Geolocation retrieved for IP: {ip}.")
    except requests.exceptions.ConnectionError:
        print("Network error. Please check your connection.")
        logging.error("Network error during geolocation API call.")

# Function to handle password recovery
def forgot_password():
    email = input("Enter your registered email: ")
    
    users = read_users()
    for user in users:
        if user['email'] == email:
            security_answer = input(f"Answer the security question: {user['security_question']} ")
            if security_answer == user['security_question']:
                new_password = input("Enter a new password: ")
                if validate_password(new_password):
                    user['password'] = hash_password(new_password).decode()
                    write_users(users)
                    print("Password reset successful!")
                    logging.info(f"Password reset for {email}.")
                else:
                    print("Password does not meet criteria.")
                    logging.warning(f"Invalid password reset criteria for {email}.")
            else:
                print("Security answer is incorrect.")
                logging.warning(f"Incorrect security answer for {email}.")
            return
    
    print("Email not found.")
    logging.warning(f"Password reset attempt with non-existent email: {email}.")

# Main application loop
def main():
    while True:
        print("\n1. Login\n2. Sign Up\n3. Forgot Password\n4. Exit")
        choice = input("Choose an option: ")
        
        if choice == '1':
            user = login()
            if user:
                # Ensure that API call happens after a successful login
                print("Fetching geolocation data...")

        elif choice == '2':
            sign_up()

        elif choice == '3':
            forgot_password()

        elif choice == '4':
            logging.info("Application exited by user.")
            break

        else:
            print("Invalid option.")
            logging.warning("Invalid menu option selected.")

if __name__ == "__main__":
    main()
