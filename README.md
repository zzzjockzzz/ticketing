J Squared Ticket HubA simple ticketing system built with Flask and SQLite, featuring ticket comments and resolutions.Setup Instructions1. PrerequisitesPython 3.6+pip2. InstallationClone the repository or download the files and navigate into the J_Squared_Ticket_Hub directory.Create a virtual environment:python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
Install the required packages:pip install -r requirements.txt
3. ConfigurationCreate a .env file in the root directory and fill in the values:SECRET_KEY: A long, random string for session security. You can generate one easily.SMTP_EMAIL: Your Gmail address (e.g., your-email@gmail.com).SMTP_PASSWORD: Your Gmail App Password. To get one, you need 2-Factor Authentication enabled on your Google account. Then go to Google App Passwords to generate a password for this app.Example .env file:SECRET_KEY='a_very_long_and_super_secret_random_string_here'
SMTP_EMAIL='your-email@gmail.com'
SMTP_PASSWORD='your-gmail-app-password'
4. Running the ApplicationOnce the dependencies are installed and your .env file is configured, run the application:python app.py
The application will start, create a tickets.db database file with the necessary tables, and be accessible at http://127.0.0.1:5000.5. Default Admin LoginEmail: jack@jsquared.comPassword: password123