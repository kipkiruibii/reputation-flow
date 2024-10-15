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
import uuid

 
# Create your views here.
def index(request):
    """
    Landing page
    """
    return render(request,'index.html')


@api_view(['POST', 'GET'])
def loginUser(request):
    """
    Login page
    """
    print('login request')
    if request.user.is_authenticated:
        # grab the member and their company
        mp=MemberProfile.objects.filter(user=request.user).first()
        print(mp)
        if not mp:
            return render(request,'404error.html')
        cm=CompanyMember.objects.filter(member=mp).first()
        if not cm:
            return render(request,'404error.html')
        user_comp=cm.company.company_id
        return redirect('dashboard',company_id=user_comp)
    
    next_url = request.GET.get('next') or request.POST.get('next') or '/home'
    if next_url == '/':
        next_url = f'{next_url}#pricing'
    if request.method == 'POST':
        name = request.POST.get('username', None)
        email = request.POST.get('email', None)
        password = request.POST.get('password', None)
        cpassword = request.POST.get('cpassword', None)
        
        # business details
        businessName = request.POST.get('businessName', None)
        businessCategory = request.POST.get('businessCategory', None)
        address1 = request.POST.get('address1', None)
        address2 = request.POST.get('address2', None)
        city = request.POST.get('city', None)
        state = request.POST.get('state', None)
        country = request.POST.get('country', None)
        telephone = request.POST.get('telephone', None)
        postal = request.POST.get('postal', None)



        type_ = request.POST.get('type', None)
        if not all([name, password]):
            return Response({'result': False, 'message': 'Please provide required details'},
                            status.HTTP_200_OK)
        if type_ == 'login':
            user = authenticate(request, username=name.strip(), password=password.strip())
            if user is not None:
                login(request, user)
                # user is authenticated
                # identify the users registered company
                mp=MemberProfile.objects.filter(user=request.user).first()
                if not mp:
                    return redirect('landing')
                cm=CompanyMember.objects.filter(member=mp).first()
                if not cm:
                    return redirect('landing')
                user_comp=cm.company.company_id
                print(user_comp)
                next_url=f'/business/id/{user_comp}/details'
                return Response({'result': True, 'message': 'success', 'redirect': next_url},
                                status.HTTP_200_OK)
            return Response({'result': False, 'message': 'Invalid credentials'},
                            status.HTTP_200_OK)
        elif type_ == 'signup':
            us = User.objects.filter(email=email.strip()).exists()
            nm = User.objects.filter(username=name.strip()).exists()
            comp = Company.objects.filter(company_name=businessName.strip()).exists()
            if us or nm:
                return Response({'result': False, 'message': 'User already exists'},
                                status.HTTP_200_OK)
            comp=Company.objects.filter(company_name=businessName.strip()).exists()
            if comp:
                return Response({'result': False, 'message': 'Company with the provided name already exists'},
                                status.HTTP_200_OK)
            if cpassword != password:
                return Response({'result': False, 'message': 'passwords do not match'},
                                status.HTTP_200_OK)
            if not all([businessName, businessCategory,address1,city,state,country,telephone,postal]):
                return Response({'result': False, 'message': 'Please provide required details'},
                                status.HTTP_200_OK)
            
            
            user = User.objects.create_user(username=name.strip(), password=password.strip(), email=email.strip())
            user.save()
            
            mp=MemberProfile(
                user=user,
                email=email)
            mp.save()

            c = Company(
                company_name=businessName,
                company_category=businessCategory,
                company_id=uuid.uuid4(),
                company_phone=telephone,
                company_address=address1,
                company_address2=address2,
                city =city,
                state=state,
                country=country,
                zipcode=postal)
            c.save()
            
            cm = CompanyMember(
                company=c,
                member=mp,
                role='Admin',
                active=True,
                is_admin=True,
                permissions={
                        'can_modify_ai_assistant':True,
                        'can_update_profile':True,
                        'can_link_unlink_account':True,
                        'can_reply_to_reviews':True,
                        'can_assign_member_review':True,
                        'can_post':True,
                        'can_see_analytics':True,
                        'can_create_team_add_member':True,
                        'can_report_issues_to_Rflow':True
                    })
            cm.save()
                # print('registered')
                # login(request, user)
            return Response({'result': True,
                                'message': 'Registration successfull.',
                                'redirect': next_url},
                            status.HTTP_200_OK)

    if request.user_agent.is_pc:
        return render(request, 'login.html', {'next': next_url})
    return render(request, 'login.html', {'next': next_url})



@login_required
def dashboard(request,company_id):
    """
    Dashboard displaying the referrals and FAQs
    """
    usr=request.user
    
    company_id=company_id
    if not company_id:
        return render(request,'404error.html')
    cm=Company.objects.filter(company_id = company_id).first()
    if not cm:
        return render(request,'404error.html')
    
    context={
        'company_name':cm.company_name,
        'company_category':cm.company_category,
        'company_profile':'https://marketplace.canva.com/EAF05vS8I5Y/2/0/1600w/canva-blue-and-yellow-modern-circle-with-chart-arrow-business-consulting-logo-design-jr327z1ASfA.jpg',
        'company_about':cm.company_about,
        'company_address':{
            'address':cm.company_address,
            'zip':cm.zipcode,
            'city':cm.city,
            'state':cm.state,
            'country':cm.country
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

def logoutUser(request):
    logout(request)
    return redirect('landing')

    