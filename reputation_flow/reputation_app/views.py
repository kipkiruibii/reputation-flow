from django.shortcuts import render,redirect

# Create your views here.
def index(request):
    """
    Landing page
    """
    return render(request,'index.html')

def login(request):
    """
    Login page
    """
    return render(request,'login.html')

def register(request):
    """
    Register page
    """
    return render(request,'register.html')

def dashboard(request,customer_id):
    """
    Dashboard displaying the referrals and FAQs
    """
    customer_id=customer_id
    print(customer_id)
    if not customer_id:
        return redirect('/')
    
    return render(request,'dashboard.html')