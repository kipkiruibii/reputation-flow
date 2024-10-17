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
    mp=MemberProfile.objects.filter(user=usr).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cm).first()
    exp_dif=(cm.company_free_trial_expiry - timezone.now()).days
    cpp=CompanyProfilePicture.objects.filter(company=cm).first()
    sc=CompanyContacts.objects.filter(company=cm).first()
    
    context={
        'company_name':cm.company_name,
        'company_category':cm.company_category,
        'company_link':cm.company_link,
        'company_profile':cpp.p_pic.url if cpp else 'https://pic.onlinewebfonts.com/thumbnails/icons_358304.svg' ,
        'company_about':cm.company_about,
        'company_subs':{
            'subscription_active':cm.company_active_subscription,
            'subscription_type':cm.company_subscription,
            'free_trial':cm.company_free_trial,
            'free_trial_expired':True if exp_dif < 0 else False,
            'free_trial_expiry':exp_dif 
            },
        'company_address':{
            'address':cm.company_address,
            'zip':cm.zipcode,
            'city':cm.city,
            'state':cm.state,
            'country':cm.country
            },
        'member_profile':{'role':cmp.role,'has_admin_priviledges':cmp.is_admin},
        'company_socials':{
            'instagram':sc.instagram if sc else None,
            'facebook':sc.facebook if sc else None,
            'twitter':sc.twitter if sc else None,
            'linkedin':sc.linkedin if sc else None,
            'email':sc.email if sc else None,
            'website':cm.company_website if cm else None,
            'whatsapp':sc.whatsapp if sc else None,
            'phone_number':cm.company_phone if cm else None,
            'youtube':sc.youtube if sc else None,
            'tiktok':sc.tiktok if sc else None,
        },
        'company_id':company_id,
        'user_permissions':{
            'can_modify_ai_assistant':False if not cmp.permissions else cmp.permissions.get('can_modify_ai_assistant',False),
            'can_update_profile':False if not cmp.permissions else cmp.permissions.get('can_update_profile',False),
            'can_link_unlink_account':False if not cmp.permissions else cmp.permissions.get('can_link_unlink_account',False),
            'can_reply_to_reviews':False if not cmp.permissions else cmp.permissions.get('can_reply_to_reviews',False),
            'can_assign_member_review':False if not cmp.permissions else cmp.permissions.get('can_assign_member_review',False),
            'can_post':False if not cmp.permissions else cmp.permissions.get('can_post',False),
            'can_see_analytics':False if not cmp.permissions else cmp.permissions.get('can_see_analytics',False),
            'can_create_team_add_member':False if not cmp.permissions else cmp.permissions.get('can_create_team_add_member',False),
            'can_report_issues_to_Rflow':False if not cmp.permissions else cmp.permissions.get('can_report_issues_to_Rflow',False)
        },
        'instagram':{
            'profile':get_instagram_user_info().get('profile_picture_url',None),
            'username':get_instagram_user_info().get('username',None),
            'date_linked':'12-oct-2024',
            'link_url':generate_instagram_login_url(),
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

@api_view(['POST'])
def fetchPosts(request):
    company_id=request.POST.get('company_id', None)

    if not company_id:
        return Response({'error':'Bad request'})
    cp=Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error':'Bad request'})
    cp=CompanyPosts.objects.filter(company=cp)
    all_posts=[]
    for p in cp:
        print('has post')
        um=UploadedMedia.objects.filter(post=p)
        med=[] 
        for m in um:
            med.append({
                'media_url':m.media.url,
                'is_video':False
            })
        
        all_posts.append({
            'platforms':p.platforms,
            'content':p.content,
            'is_uploaded':p.is_uploaded,
            'is_scheduled':p.is_scheduled,
            'tags':p.tags,
            'has_media':p.has_media,
            'date_uploaded':p.date_uploaded,
            'media':med
            
        })
    context={
        'posts':all_posts,
    }
    print(context)
    return render(request,'dashboard.html',context=context)
  
    
def logoutUser(request):
    logout(request)
    return redirect('landing')

def companyProfile(request,company_name):
    if not company_name:
        return render(request,'404error.html')
    cn=Company.objects.filter(company_link_name=company_name).first()
    if not cn:
        return render(request,'404error.html')


@api_view(['POST'])  
def updateBusinessProfile(request):
    company_id = request.POST.get('company_id',None)
    email = request.POST.get('email',None)
    phone = request.POST.get('phone',None)
    about = request.POST.get('about',None)
    website = request.POST.get('website',None)
    whatsapp = request.POST.get('whatsapp',None)
    instagram = request.POST.get('instagram',None)
    tiktok = request.POST.get('tiktok',None)
    youtube = request.POST.get('youtube',None)
    twitter = request.POST.get('twitter',None)
    linkedin = request.POST.get('linkedin',None)
    facebook = request.POST.get('facebook',None)
    # Get image file from FILES
    image = request.FILES.get('image',None)
    cm = Company.objects.filter(company_id = company_id).first()
    if not cm:
        return Response({'updated':False})
    if image:
        cpp=CompanyProfilePicture.objects.filter(company=cm).first()
        if cpp:
            cpp.p_pic=image
        else:
            cpp= CompanyProfilePicture(
                company=cm,
                p_pic=image
            ) 
        cpp.save()
    cc = CompanyContacts.objects.filter(company = cm).first()
    if cc:
        cc.instagram=instagram if instagram else cc.instagram
        cc.whatsapp=whatsapp if whatsapp else cc.whatsapp
        cc.tiktok=tiktok if tiktok else cc.tiktok
        cc.youtube=youtube if youtube else cc.youtube
        cc.twitter=twitter if twitter else cc.twitter
        cc.linkedin=linkedin if linkedin else cc.linkedin
        cc.email=email if email else cc.email
        cc.facebook=facebook if facebook else cc.facebook
        cc.save()
    else:
        cc=CompanyContacts(
                company=cm,
                instagram=instagram,
                facebook=facebook,
                whatsapp=whatsapp,
                twitter=twitter,
                tiktok=tiktok,
                email=email,
                linkedin=linkedin,
                youtube=youtube
        )
        cc.save()
    cm.company_phone=phone if phone else cm.company_phone
    cm.company_website = website if website else cm.company_website
    cm.company_about= about if about else cm.company_about
    cm.save()

    return Response({'updated':True})
# social platforms

def generate_instagram_login_url():
    client_id = '1627034847853223'  # Your Instagram App ID
    redirect_uri =  'https://858d-197-237-137-103.ngrok-free.app/instagram-redirect' # Your Redirect URI
    scope = "instagram_basic,instagram_manage_comments,instagram_manage_messages,instagram_content_publish,pages_show_list"
    oauth_url = (
        f"https://www.facebook.com/v14.0/dialog/oauth?"
        f"client_id={client_id}&redirect_uri={redirect_uri}&"
        f"scope={scope}&response_type=code"
    )
    return oauth_url

import requests

def get_instagram_user_info():
    access_token='IGQWRQaUNyNWNLYlNmVmtSRkExUVROLWYySzZANbDBtY2Q2NXZA5QVVSYjloaWpmdTM5dVE1bmwxbHhRc3lZAMEtNV3llZAVdybGNTeTJpMWhqS2wtS0pEMFJMQnNwZAUZAOQWZAjVjBvcE90M2pHSkdzMGJKalZA0OTN3RXcZD'

    url = 'https://graph.instagram.com/me'
    params = {
        'fields': 'id,username,account_type,profile_picture_url',
        'access_token': access_token
    }
    response = requests.get(url, params=params)
    return response.json()

# Use the token you retrieved manually

@csrf_exempt
def instagram_post_url(request):
    print('here we go')
    return redirect('landing')
