from django.shortcuts import render

# Create your views here.
def index(requests):
    """
    Landing page
    """
    return render('landing.html')

def login(request):
    """
    Login page
    """
    return render('login.html')

def register(request):
    """
    Register page
    """
    return render('register.html')

def dashboard(request,customer_id):
    """
    Dashboard displaying the referrals and FAQs
    """
    
    return render('dashboard.html')