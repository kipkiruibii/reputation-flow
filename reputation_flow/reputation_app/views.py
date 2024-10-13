from django.shortcuts import render,redirect
import json
import traceback
from datetime import timedelta
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import *
from paypal.standard.forms import PayPalPaymentsForm
from django.conf import settings
import uuid
from django.urls import reverse
# firebase.py
import firebase_admin
from firebase_admin import credentials, auth

# Create your views here.
def index(request):
    """
    Landing page
    """
    return render(request,'index.html')


@api_view(['POST', 'GET'])
def login(request):
    """
    Login page
    """
    if request.user.is_authenticated:
        # grab the member and their company
        return redirect('dashboard')
    next_url = request.GET.get('next') or request.POST.get('next') or '/home'
    if next_url == '/':
        next_url = f'{next_url}#pricing'
    if request.method == 'POST':
        name = request.POST.get('username', None)
        email = request.POST.get('email', None)
        password = request.POST.get('password', None)
        cpassword = request.POST.get('cpassword', None)
        type_ = request.POST.get('type', None)
        if not all([name, password]):
            return Response({'result': False, 'message': 'Please provide required details'},
                            status.HTTP_200_OK)
        if type_ == 'login':
            user = authenticate(request, username=name.strip(), password=password.strip())
            if user is not None:
                login(request, user)

                return Response({'result': True, 'message': 'success', 'redirect': next_url},
                                status.HTTP_200_OK)
            return Response({'result': False, 'message': 'Invalid credentials'},
                            status.HTTP_200_OK)
        elif type_ == 'signup':
            us = User.objects.filter(email=email.strip()).exists()
            nm = User.objects.filter(username=name.strip()).exists()
            if us or nm:
                return Response({'result': False, 'message': 'User already exists'},
                                status.HTTP_200_OK)
            if cpassword != password:
                return Response({'result': False, 'message': 'passwords do not match'},
                                status.HTTP_200_OK)

            user = User.objects.create_user(username=name.strip(), password=password.strip(), email=email.strip())
            user.save()
            # print('registered')
            # login(request, user)
            return Response({'result': True,
                             'message': 'Registration successfull. Account verification link sent to your email. Please verify',
                             'redirect': next_url},
                            status.HTTP_200_OK)

    if request.user_agent.is_pc:
        return render(request, 'login.html', {'next': next_url})
    return render(request, 'login.html', {'next': next_url})


def register(request):
    """
    Register page
    """
    
    
    return render(request,'register.html')

@login_required
def dashboard(request,company_id):
    """
    Dashboard displaying the referrals and FAQs
    """
    usr=request.user
    
    company_id=company_id
    print(company_id)
    if not company_id:
        return redirect('/')
    context={
        'company_name':None,
        'company_profile':'https://marketplace.canva.com/EAF05vS8I5Y/2/0/1600w/canva-blue-and-yellow-modern-circle-with-chart-arrow-business-consulting-logo-design-jr327z1ASfA.jpg',
        'company_about':'This is a dummy about',
        'company_address':{
            'address':None,
            'zip':None,
            'city':None,
            'state':None,
            'country':None
            },
        'company_socials':{
            'instagram':None,
            'facebook':'https://www.facebook.com',
            'twitter':None,
            'linkedin':None,
            'reddit':None,
            'email':None,
            'website':None,
            'whatsapp':None,
            'phone_number':None
        },
        'company_id':company_id,
        'user_permissions':{
            'can_modify_ai_assistant':False,
            'can_update_profile':False,
            'can_link_unlink_account':True,
            'can_reply_to_reviews':False,
            'can_assign_member_review':False,
            'can_post':False,
            'can_see_analytics':False,
            'can_create_team_add_member':False,
            'can_report_issues_to_Rflow':False
        },
        'instagram':{
            'profile':'https://marketplace.canva.com/EAF05vS8I5Y/2/0/1600w/canva-blue-and-yellow-modern-circle-with-chart-arrow-business-consulting-logo-design-jr327z1ASfA.jpg',
            'username':'Deel Instagram',
            'date_linked':'12-oct-2024',
            'linked':True,
            'active':True
        },
        'facebook':{
            'profile':'',
            'username':'',
            'date_linked':'',
            'linked':False,
            'active':True
        },
        'twitter':{
            'profile':'',
            'username':'',
            'date_linked':'',
            'linked':False,
            'active':True
            },
        'youtube':{
            'profile':'',
            'username':'',
            'date_linked':'',
            'linked':False,
            'active':False
        },
        'google':{
            'profile':'',
            'username':'',
            'date_linked':'',
            'linked':False,
            'active':False
        },
        'tiktok':{
            'profile':'',
            'username':'',
            'date_linked':'',
            'linked':False,
            'active':False
        },
       }
    return render(request,'dashboard.html',context=context)

def logout(request):
    logout(request.user)
    return redirect('landing')

