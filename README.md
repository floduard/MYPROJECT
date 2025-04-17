# MULTIFACTOR AUTHENTICATION SYSTEM

# 1. Clone the repository
git clone https://github.com/floduard/MYPROJECT.git

# 2. Navigate into the project directory
cd MYPROJECT

# 3. (Optional but recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate  
# On Windows: venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run database migrations
python manage.py migrate

# 6. Create a superuser for admin access
python manage.py createsuperuser

# 7. Run the development server
python manage.py runserver
