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
import requests
import bleach
import google_auth_oauthlib.flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import secrets
import hashlib
import base64
import urllib.parse
# 1. Generate a State Token for CSRF protection
def generate_state_token():
    return secrets.token_urlsafe(16)  # Generates a random URL-safe token

# 2. Generate a PKCE Challenge Token
def generate_pkce_challenge():
    # Step 1: Generate a code verifier (random 43-128 character string)
    code_verifier = secrets.token_urlsafe(64)[:128]  # Limiting to 128 chars

    # Step 2: Create a code challenge by hashing the verifier
    challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode("utf-8")

    return code_verifier, code_challenge


 # Set your Instagram App credentials
INSTAGRAM_CLIENT_ID = settings.INSTAGRAM_CLIENT_ID
INSTAGRAM_CLIENT_SECRET = settings.INSTAGRAM_CLIENT_SECRET
INSTAGRAM_REDIRECT_URI = settings.INSTAGRAM_REDIRECT_URI
 
# Define the allowed HTML tags and attributes
ALLOWED_TAGS = ['p', 'b', 'i', 'u', 'strong', 'em', 'a', 'img', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'li', 'ol', 'br']
ALLOWED_ATTRIBUTES = {
    '*': ['class', 'style'],  # Allow 'class' and 'style' on all tags
    'a': ['href', 'title'],
    'img': ['src', 'alt'],
}
ALLOWED_STYLES = ['color', 'font-weight', 'text-decoration', 'font-style']  # Allowed CSS styles

def clean_html(input_html):
    # Sanitize the input HTML using Bleach
    clean_html = bleach.clean(input_html,
                              tags=ALLOWED_TAGS,
                              attributes=ALLOWED_ATTRIBUTES,
                            #   styles=ALLOWED_STYLES,
                              strip=True)  # strip=True removes disallowed tags completely
    return clean_html
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
                next_url=f'/b/{user_comp}/dashboard'
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
        # 'company_profile':cpp.p_pic.url if cpp else 'https://pic.onlinewebfonts.com/thumbnails/icons_358304.svg' ,
        'company_profile': 'https://pic.onlinewebfonts.com/thumbnails/icons_358304.svg' ,
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
            # 'profile':get_instagram_user_info().get('profile_picture_url',None),
            # 'username':get_instagram_user_info().get('username',None),
            'date_linked':'',
            'link_url':get_instagram_auth_url(company_id),
            'linked':False,
            'active':False
        },
        'facebook':{
            'profile':'',
            'username':'',
            'date_linked':'',
            'link_url':get_facebook_auth_url(company_id),
            'linked':False,
            'active':True
        },
        'twitter':{
            'profile':'',
            'username':'',
            'date_linked':'',
            'link_url':twitter_auth_link(),
            'linked':False,
            'active':True
            },
        'youtube':{
            'profile':'',
            'username':'',
            'date_linked':'',
            # 'link_url':youtube_auth_link(),
            'linked':False,
            'active':False
        },
        'google':{
            'profile':'',
            'username':'',
            'date_linked':'',
            # 'link_url':google_business_auth_link(),
            'linked':False,
            'active':False
        },
        'tiktok':{
            'profile':'',
            'username':'',
            'date_linked':'',
            'link_url':tiktok_auth_link(),
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


@api_view(['POST'])
def fetchTeams(request):
    company_id=request.POST.get('company_id', None)

    if not company_id:
        return Response({'error':'Bad request'})
    cp=Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error':'Bad request'})
    mp=MemberProfile.objects.filter(user=request.user).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cp).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cp).first()

    context={
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
        'all_teams':CompanyTeam.objects.filter(company=cp).order_by('-pk'),
    }
    return render(request,'dashboard.html',context=context)
    
  
#  create team
@login_required
@api_view(['POST'])
def createTeam(request):
    company_id=request.POST.get('company_id', None)
    team_name=request.POST.get('team_name', None)
    team_about=request.POST.get('team_about', None)
    mp=MemberProfile.objects.filter(user=request.user).first()
    if not mp:
        return Response({'error':'Forbidden'})
    if not all([company_id,team_name,team_about]):
        return Response({'error':'Bad request'})
    cp=Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error':'Bad request'})
    ct=CompanyTeam.objects.filter(company=cp,team_name=team_name).first()
    if ct:
        return Response({'error':'Team with similar name already exist'})
    ct=CompanyTeam(
            company=cp,
            team_name=team_name,
            team_about=team_about
    )

    ct.save()
    ct.members.add(mp)
    ct.save()
    mp=MemberProfile.objects.filter(user=request.user).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cp).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cp).first()

    context={
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
        'all_teams':CompanyTeam.objects.filter(company=cp).order_by('-pk'),
        'invite_links':CompanyTeamInviteLinks.objects.filter(team=ct).order_by('-pk')
    }
    return render(request,'dashboard.html',context=context)


# delete team 
@api_view(['POST'])
def deleteTeam(request):
    company_id=request.POST.get('company_id', None)
    team_id=request.POST.get('team_id', None)
    if not all([company_id,team_id]):
        return Response({'error':'Bad request'})
    cp=Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error':'Bad request'})
    ct=CompanyTeam.objects.filter(company=cp,id=team_id).first()
    if not ct:
        return Response({'error':'Bad request'})
    ct.delete()
    mp=MemberProfile.objects.filter(user=request.user).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cp).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cp).first()

    context={
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
        'all_teams':CompanyTeam.objects.filter(company=cp).order_by('-pk'),
        'invite_links':CompanyTeamInviteLinks.objects.filter(team=ct).order_by('-pk')

    }
    return render(request,'dashboard.html',context=context)
   
# get team 
@api_view(['POST'])
def viewTeam(request):
    company_id=request.POST.get('company_id', None)
    team_id=request.POST.get('team_id', None)
    if not all([company_id,team_id]):
        return Response({'error':'Bad request'})
    cp=Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error':'Bad request'}) 
    ct=CompanyTeam.objects.filter(company=cp,id=team_id).first()
    if not ct:
        return Response({'error':'Bad request'})
    mp=MemberProfile.objects.filter(user=request.user).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cp).first()
    cmp=CompanyMember.objects.filter(member=mp,company=cp).first()
    
    chat_messages=[]
    for cm in CompanyTeamChat.objects.filter(team=ct):
        prf=MemberPP.objects.filter(member=mp).first()
        chat_messages.append(
            {
              'me':True if cm.sender==mp else False, 
              'dp':prf.pic.url if prf else None,
              'sender':cm.sender,
              'message':cm.message,
              'date_sent':cm.date_sent.strftime('%m/%y %H:%M')
            }
        )

    t_mem=[]
    for r in ct.members.all():
        profile_pic=MemberPP.objects.filter(member=r).first()
        t_mem.append(   
            {'name':r.user.username,
             'profile_pic':profile_pic.pic if profile_pic else None
             }
        )
    t_actv=[]
    for t_a in CompanyTeamActivity.objects.filter(team=ct).order_by('-pk'):
        tm_bef=(timezone.now-t_a.date_created)
        ti_b=''
        if tm_bef<86400:
            ti_b=tm_bef//3600 #how many hours ago
            ti_b=ti_b +' hours ago'
            if ti_b<0:
                ti_b=tm_bef//60 # how many minutes ago
                ti_b=ti_b +' minutes ago'
        t_actv.append(
            {
                'title':t_a.title,
                'time_from':t_a.date_created,
                'date_created':ti_b,
            }
        )
        
    context={
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
        'team':ct,
        'all_teams':CompanyTeam.objects.filter(company=cp).order_by('-pk'),
        'invite_links':CompanyTeamInviteLinks.objects.filter(team=ct).order_by('-pk'),
        'team_members':t_mem,
        'team_files':CompanyTeamFiles.objects.filter(team=ct).order_by('-pk'),
        'announcements':CompanyTeamAnnouncements.objects.filter(team=ct).order_by('-pk'),
        'activities':t_actv,
        'chat_messages':chat_messages

    }
    return render(request,'dashboard.html',context=context)

# create invite link
@api_view(['POST'])
def generateInviteLink(request):
    company_id=request.POST.get('company_id', None)
    team_id=request.POST.get('team_id', None)
    members_num=request.POST.get('members_number', None)
    members_perm=request.POST.get('members_permissions', None)
    if not all([company_id,team_id,members_num,members_perm]):
        return Response({'error':'Bad request'})
    cp=Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error':'Bad request'}) 
    ct=CompanyTeam.objects.filter(company=cp,id=team_id).first()
    if not ct:
        return Response({'error':'Bad request'})
    print(members_perm)
    permissions=members_perm.split(',')
    cleaned_permissions = [permission.strip().replace('\r', '').replace('\n', ' ') for permission in permissions]
    uid=uuid.uuid4()
    url_link=f'https://www.revflow.co/invite/{uid}'

    # save the link
    cil=CompanyTeamInviteLinks(
            team=ct,
            link=url_link,
            permissions=cleaned_permissions,
            max_members=members_num
    )
    cil.save()

    
    return Response({'result':url_link})

# get team 
@api_view(['POST'])
def sendChat(request):
    company_id=request.POST.get('company_id', None)
    team_id=request.POST.get('team_id', None)
    message=request.POST.get('message', None)
    if not all([message,team_id,company_id]):
        return Response({'error':'Bad request'})
    usr=MemberProfile.objects.filter(user=request.user).first()
    if not usr:
        return Response({'error':'Bad request'})
    ct=CompanyTeam.objects.filter(id=team_id).first()
    if not ct:
        return Response({'error':'Bad request'})
    # check if user if part of the team
    if not ct.members.filter(id=usr.id).exists():
        print('member dont exist')

        return Response({'error':'Bad request'})
    ctc=CompanyTeamChat(
            team=ct,
            sender=usr,
            message=message,
        )   
    ctc.save()
    chat_messages=[]
    for cm in CompanyTeamChat.objects.filter(team=ct):
        prf=MemberPP.objects.filter(member=usr).first()
        chat_messages.append(
            {
              'me':True if cm.sender==usr else False, 
              'dp':prf.pic.url if prf else None,
              'sender':cm.sender,
              'message':cm.message,
              'date_sent':cm.date_sent.strftime('%m/%y %H:%M')
            }
        )
    context={
        'chat_messages':chat_messages
    }
    return render(request,'dashboard.html',context=context)

@api_view(['POST'])
def uploadPost(request):
    company_id=request.POST.get('company_id', None)           
    content=request.POST.get('content', None) 
    platforms=request.POST.get('platforms', None)           
    tags=request.POST.get('tags', None)           
    media = request.FILES.get('media',None)
    sheduled=request.POST.get('scheduled', False)  
    if not all([company_id,content]):
        return Response({'error':'Bad request'})
    cp=Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error':'Bad request'}) 
    
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
        cc.instagram=instagram 
        cc.whatsapp=whatsapp 
        cc.tiktok=tiktok 
        cc.youtube=youtube 
        cc.twitter=twitter 
        cc.linkedin=linkedin 
        cc.email=email
        cc.facebook=facebook 
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
    cm.company_about= clean_html(about) if about else cm.company_about
    cm.save()

    return Response({'updated':True})
# social platforms

def instagram_upload_content(request):
    """View to handle content upload to Instagram."""
    if request.method == 'POST':
        image_url = request.POST.get('image_url')  # Image URL to upload
        caption = request.POST.get('caption')  # Caption for the post

        access_token = request.session.get('access_token')
        user_id = request.session.get('user_id')

        # Step 1: Create Media Object
        create_media_url = f'https://graph.facebook.com/v13.0/{user_id}/media'
        media_response = requests.post(create_media_url, {
            'image_url': image_url,
            'caption': caption,
            'access_token': access_token
        })

        media_data = media_response.json()

        if 'id' in media_data:
            creation_id = media_data['id']

            # Step 2: Publish Media
            publish_url = f'https://graph.facebook.com/v13.0/{user_id}/media_publish'
            publish_response = requests.post(publish_url, {
                'creation_id': creation_id,
                'access_token': access_token
            })

            publish_data = publish_response.json()

            if 'id' in publish_data:
                return render(request, 'upload_success.html', {'post_id': publish_data['id']})
            else:
                return render(request, 'error.html', {'error': publish_data.get('error', {}).get('message', 'Failed to publish media.')})

        return render(request, 'error.html', {'error': media_data.get('error', {}).get('message', 'Failed to create media object.')})

    return render(request, 'upload_content.html')

def get_instagram_auth_url(company_id):
    """
    Generates the Instagram OAuth URL with a state parameter for session integrity.

    :param company_id: Unique identifier for the Company, such as a database Company ID.
    :return: OAuth URL with state parameter for user identification.
    """
    # Encode the user_id or other identifying data in the state parameter
    state = urllib.parse.quote_plus(str(company_id))  # Ensure URL encoding for special characters
    oauth_url = (
        f"https://www.facebook.com/v21.0/dialog/oauth"
        f"?client_id={settings.INSTAGRAM_CLIENT_ID}"
        f"&redirect_uri={settings.INSTAGRAM_REDIRECT_URI}"
        f"&scope=instagram_basic,instagram_content_publish,instagram_manage_insights,pages_show_list,pages_manage_posts,pages_read_engagement,pages_manage_engagement"
        f"&state={state}"
        )
    return oauth_url

def get_facebook_auth_url(company_id):
    """
    Generates the Instagram OAuth URL with a state parameter for session integrity.

    :param company_id: Unique identifier for the Company, such as a database Company ID.
    :return: OAuth URL with state parameter for user identification.
    """
    # Encode the user_id or other identifying data in the state parameter
    state = urllib.parse.quote_plus(str(company_id))  # Ensure URL encoding for special characters
    oauth_url = (
        f"https://www.facebook.com/v21.0/dialog/oauth"
        f"?client_id={settings.FACEBOOK_APP_ID}"
        f"&redirect_uri={settings.FACEBOOK_REDIRECT_URI}"
        f"&scope=pages_show_list,pages_manage_posts,pages_read_engagement,pages_manage_engagement"
        f"&state={state}"
        )
    return oauth_url


@api_view(['GET'])  
def instagram_callback(request):
    code = request.GET.get('code')
    state = request.GET.get("state")  # Retrieve the state parameter
    company_id = urllib.parse.unquote_plus(state)  # Decode the state to get the original user_id
    token_url = f"https://graph.facebook.com/v21.0/oauth/access_token?client_id={settings.FACEBOOK_APP_ID}&redirect_uri={settings.FACEBOOK_REDIRECT_URI}&client_secret={settings.FACEBOOK_APP_SECRET}&code={code}"
    response = requests.get(token_url)
    data = response.json()
    print(data)
    access_token = data.get('access_token') 
    cm=Company.objects.filter(company_id = company_id).first()
    if not cm:
        return redirect('dashboard')
    ci=CompanyInstagram.objects.filter(company=cm).first()
    pg_id=get_facebook_ig_page_id(access_token)
    inst_id = get_instagram_account_id(access_token,pg_id)
    insgts=get_instagram_account_insights(access_token,inst_id)
    l_lived_token=get_long_lived_token(access_token)
    if ci:
        ci.short_lived_token=access_token
        ci.account_id=inst_id
        ci.long_lived_token=l_lived_token
        ci.linked=True
        ci.active=True
        ci.account_name=insgts['username']
        ci.account_type=insgts['account_type']
        ci.profile_url=insgts['profile_picture_url']
        ci.followers_trend.add(insgts['followers_count'])
        ci.impressions.add(insgts['impressions'])
        ci.reach.add(insgts['reach'])
        ci.profile_views.add(insgts['profile_views'])
        ci.save()
        
    else:
        ci = CompanyInstagram(
            short_lived_token=access_token,
            account_id=inst_id,
            long_lived_token=l_lived_token,
            linked=True,
            active=True,
            account_name=insgts['username'],
            account_type=insgts['account_type'],
            profile_url=insgts['profile_picture_url']
        )
        ci.followers_trend.add(insgts['followers_count'])
        ci.impressions.add(insgts['impressions'])
        ci.reach.add(insgts['reach'])
        ci.profile_views.add(insgts['profile_views'])
        ci.save()
        
    cf=CompanyFacebook.objects.filter(company=cm).first()
    insgts=get_facebook_page_insights(access_token,pg_id)
    if cf:
        cf.short_lived_token=access_token
        cf.account_id=pg_id
        cf.long_lived_token=l_lived_token
        cf.linked=True
        cf.active=True
        cf.page_id=pg_id
        cf.account_name=insgts['page_name']
        cf.profile_url=insgts['p_picture']
        cf.followers_trend.add(insgts['fan_count'])
        cf.impressions.add(insgts['page_impressions'])
        cf.page_negative_feedback.add(insgts['page_negative_feedback'])
        cf.profile_views.add(insgts['page_views_total'])
        cf.page_engaged_users.add(insgts['page_engaged_users'])
        cf.page_fans.add(insgts['page_fans'])
        cf.save()
    else:
        cf = CompanyFacebook(
            short_lived_token=access_token,
            account_id=pg_id,
            long_lived_token=l_lived_token,
            linked=True,
            active=True,
            page_id=pg_id,
            account_name=insgts['page_name'],
            profile_url=insgts['p_picture'],
        )
        cf.followers_trend.add(insgts['fan_count'])
        cf.impressions.add(insgts['page_impressions'])
        cf.page_negative_feedback.add(insgts['page_negative_feedback'])
        cf.profile_views.add(insgts['page_views_total'])
        cf.page_engaged_users.add(insgts['page_engaged_users'])
        cf.page_fans.add(insgts['page_fans'])
        cf.save()

    return redirect('dashboard')
    
def get_facebook_ig_page_id(page_access_token):
    page_url = f"https://graph.facebook.com/v21.0/me/accounts"
    params = {"access_token": page_access_token}
    response = requests.get(page_url,params=params)
    page_data = response.json()
    page_id = page_data['data'][0]['id']
    return page_id


def get_instagram_account_id(page_access_token,page_id):
    # Get Instagram Business Account ID
    insta_url = f"https://graph.facebook.com/v21.0/{page_id}?fields=instagram_business_account&access_token={page_access_token}"
    response = requests.get(insta_url)
    insta_data = response.json()
    return insta_data['instagram_business_account']['id']

def post_to_instagram(insta_account_id, page_access_token, image_url, caption):
    # Step 1: Create a container
    container_url = f"https://graph.facebook.com/v21.0/{insta_account_id}/media"
    container_params = {
        "image_url": image_url,
        "caption": caption,
        "access_token": page_access_token,
    }
    container_response = requests.post(container_url, data=container_params)
    container_data = container_response.json()
    container_id = container_data['id']

    # Step 2: Publish the container
    publish_url = f"https://graph.facebook.com/v21.0/{insta_account_id}/media_publish"
    publish_params = {
        "creation_id": container_id,
        "access_token": page_access_token,
    }
    publish_response = requests.post(publish_url, data=publish_params)
    publish_data = publish_response.json()
    return publish_data

def get_long_lived_token(short_lived_token):
    exchange_url = f"https://graph.facebook.com/v21.0/oauth/access_token"
    params = {
        "grant_type": "fb_exchange_token",
        "client_id": settings.FACEBOOK_APP_ID,
        "client_secret": settings.FACEBOOK_APP_SECRET,
        "fb_exchange_token": short_lived_token,
    }
    response = requests.get(exchange_url, params=params)
    data = response.json()
    return data.get("access_token")

def refresh_long_lived_token(current_long_lived_token):
    """
    Refreshes the Facebook long-lived access token, extending its validity by 60 days.
    """
    refresh_url = "https://graph.facebook.com/v21.0/oauth/access_token"
    params = {
        "grant_type": "fb_exchange_token",
        "client_id": settings.FACEBOOK_APP_ID,
        "client_secret": settings.FACEBOOK_APP_SECRET,
        "fb_exchange_token": current_long_lived_token,
    }
    
    response = requests.get(refresh_url, params=params)
    data = response.json()
    
    # Check for errors
    if "error" in data:
        raise Exception(f"Error refreshing token: {data['error']['message']}")
    
    # Extract the new token and its expiration info
    new_long_lived_token = data.get("access_token")
    expires_in = data.get("expires_in")  # typically 5184000 seconds (60 days)

    # You would generally save this new_long_lived_token in your database
    # with its expiry information to track it.

    return new_long_lived_token, expires_in


def get_instagram_account_insights(access_token, instagram_account_id):
    """
    Retrieves basic data, profile information, and analytics for an Instagram Business account.
    
    :param access_token: The long-lived Instagram access token.
    :param instagram_account_id: The ID of the Instagram Business account.
    :return: A dictionary containing basic account metrics, username, and profile picture.
    """
    url = f"https://graph.facebook.com/v14.0/{instagram_account_id}"
    params = {
        "fields": "followers_count,media_count,account_type,username,profile_picture_url",
        "access_token": access_token
    }
    
    response = requests.get(url, params=params)
    data = response.json()

    # Check for errors in the response
    if "error" in data:
        raise Exception(f"Error fetching insights: {data['error']['message']}")
    
    # Additional insights (optional)
    insights_url = f"https://graph.facebook.com/v14.0/{instagram_account_id}/insights"
    insights_params = {
        "metric": "impressions,reach,profile_views",
        "period": "day",
        "access_token": access_token
    }

    insights_response = requests.get(insights_url, params=insights_params)
    insights_data = insights_response.json()

    if "error" in insights_data:
        raise Exception(f"Error fetching insights data: {insights_data['error']['message']}")

    # Combine account data and insights for easier access
    account_data = {
        "followers_count": data.get("followers_count"),
        "media_count": data.get("media_count"),
        "account_type": data.get("account_type"),
        "username": data.get("username"),
        "profile_picture_url": data.get("profile_picture_url"),
        "impressions": insights_data["data"][0]["values"] if "data" in insights_data else None,
        "reach": insights_data["data"][1]["values"] if "data" in insights_data else None,
        "profile_views": insights_data["data"][2]["values"] if "data" in insights_data else None,
    }

    return account_data

def get_facebook_page_insights(access_token,page_id):
    url = f"https://graph.facebook.com/v21.0/{page_id}"
    params = {
        "fields": "name,username,picture,fan_count",
        "access_token": access_token
    }
    
    response = requests.get(url, params=params)   
    profile_info=response.json()
    
    url = f"https://graph.facebook.com/v21.0/{page_id}/insights"
    params = {
        "metric": "page_impressions,page_engaged_users,page_fans,page_views_total,page_negative_feedback",
        "access_token": access_token
    }
    
    response = requests.get(url, params=params)
    page_insights=response.json()
    return {
            'page_name':profile_info.get("name"),
            'page_username':profile_info.get("username"),
            'fan_count':profile_info.get("username"),
            'p_picture':profile_info.get("picture", {}).get("data", {}).get("url"),
            'page_impressions':page_insights.get('page_impressions'),
            'page_engaged_users':page_insights.get('page_engaged_users'),
            'page_fans':page_insights.get('page_fans'),
            'page_views_total':page_insights.get('page_fans'),
            'page_negative_feedback':page_insights.get('page_negative_feedback')
            }
    
    
def get_facebook_user_pages(access_token):
    pages_url = f"https://graph.facebook.com/v21.0/me/accounts?access_token={access_token}"
    response = requests.get(pages_url)
    return response.json()  # This will return a list of pages the user manages


def facebook_create_post(page_id, message, access_token):
    post_url = f"https://graph.facebook.com/v21.0/{page_id}/feed"
    data = {
        'message': message,
        'access_token': access_token
    }
    response = requests.post(post_url, data=data)
    return response.json()  # This will return the result of the post creation


def facebook_callback(request):
    code = request.GET.get('code')
    state = request.GET.get("state")  # Retrieve the state parameter
    company_id = urllib.parse.unquote_plus(state)  # Decode the state to get the original user_id
    token_url = f"https://graph.facebook.com/v21.0/oauth/access_token?client_id={settings.FACEBOOK_APP_ID}&redirect_uri={settings.FACEBOOK_REDIRECT_URI}&client_secret={settings.FACEBOOK_APP_SECRET}&code={code}"
    response = requests.get(token_url)
    data = response.json()
    print(data)
    access_token = data.get('access_token') 
    cm=Company.objects.filter(company_id = company_id).first()
    if not cm:
        return redirect('dashboard')
    pg_id=get_facebook_ig_page_id(access_token)
    l_lived_token=get_long_lived_token(access_token)
    cf=CompanyFacebook.objects.filter(company=cm).first()
    insgts=get_facebook_page_insights(access_token,pg_id)
    if cf:
        cf.short_lived_token=access_token
        cf.account_id=pg_id
        cf.long_lived_token=l_lived_token
        cf.linked=True
        cf.active=True
        cf.page_id=pg_id
        cf.account_name=insgts['page_name']
        cf.profile_url=insgts['p_picture']
        cf.followers_trend.add(insgts['fan_count'])
        cf.impressions.add(insgts['page_impressions'])
        cf.page_negative_feedback.add(insgts['page_negative_feedback'])
        cf.profile_views.add(insgts['page_views_total'])
        cf.page_engaged_users.add(insgts['page_engaged_users'])
        cf.page_fans.add(insgts['page_fans'])
        cf.save()
    else:
        cf = CompanyFacebook(
            short_lived_token=access_token,
            account_id=pg_id,
            long_lived_token=l_lived_token,
            linked=True,
            active=True,
            page_id=pg_id,
            account_name=insgts['page_name'],
            profile_url=insgts['p_picture'],
        )
        cf.followers_trend.add(insgts['fan_count'])
        cf.impressions.add(insgts['page_impressions'])
        cf.page_negative_feedback.add(insgts['page_negative_feedback'])
        cf.profile_views.add(insgts['page_views_total'])
        cf.page_engaged_users.add(insgts['page_engaged_users'])
        cf.page_fans.add(insgts['page_fans'])
        cf.save()

    return redirect('dashboard')


def tiktok_auth_link():
    """Generates the TikTok OAuth authorization link."""
    scope_param = " ".join(settings.TIKTOK_SCOPES)
    auth_url = (
        f"https://www.tiktok.com/auth/authorize/"
        f"?client_key={settings.TIKTOK_CLIENT_ID}"
        f"&redirect_uri={settings.TIKTOK_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={scope_param}"
    )
    return auth_url


def tiktok_callback(request):
    """Handles the TikTok callback and exchanges code for an access token."""
    code = request.GET.get('code')
    token_url = "https://open.tiktokapis.com/v2/oauth/token/"
    data = {
        "client_key": settings.TIKTOK_CLIENT_ID,
        "client_secret": settings.TIKTOK_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.TIKTOK_REDIRECT_URI,
    }
    response = requests.post(token_url, data=data)
    access_token = response.json().get("access_token")

    if not access_token:
        return HttpResponse("Failed to get access token", status=400)

    # Store access token in session or database for later use
    request.session["tiktok_access_token"] = access_token
    print(access_token)
    return HttpResponse("Authenticated with TikTok!")


def tiktok_upload_video(request):
    """Uploads a video to TikTok."""
    access_token = request.session.get("tiktok_access_token")
    video_file_path = "path/to/video.mp4"  # Update to the actual path or pass it in a form

    if not access_token:
        return JsonResponse({"error": "User is not authenticated"}, status=403)

    headers = {"Authorization": f"Bearer {access_token}"}

    # Step 1: Initialize upload
    init_url = "https://open.tiktokapis.com/v2/post/publish/inbox/video/init/"
    init_response = requests.post(init_url, headers=headers)

    if init_response.status_code != 200:
        return JsonResponse({"error": "Failed to initialize upload"})

    upload_url = init_response.json().get("data").get("upload_url")

    # Step 2: Upload video file
    with open(video_file_path, "rb") as video_file:
        upload_response = requests.post(upload_url, files={"video": video_file})

    if upload_response.status_code != 200:
        return JsonResponse({"error": "Failed to upload video"})

    return JsonResponse(upload_response.json())

def get_tiktok_comments(request, video_id):
    """Retrieves comments on a specific TikTok video."""
    access_token = request.session.get("tiktok_access_token")
    
    if not access_token:
        return JsonResponse({"error": "User is not authenticated"}, status=403)

    headers = {"Authorization": f"Bearer {access_token}"}
    params = {
        "video_id": video_id,
        "count": 20  # Adjust as needed
    }
    comments_url = "https://open.tiktokapis.com/v2/comment/list/"
    response = requests.get(comments_url, headers=headers, params=params)

    if response.status_code != 200:
        return JsonResponse({"error": "Failed to fetch comments"})

    return JsonResponse(response.json())

def twitter_auth_link():
    """Generates the Twitter OAuth 2.0 authorization link."""
    state_token = generate_state_token()
    code_verifier, code_challenge = generate_pkce_challenge()
    auth_url = (
        f"https://twitter.com/i/oauth2/authorize?response_type=code"
        f"&client_id={settings.TWITTER_CLIENT_ID}"
        f"&redirect_uri={settings.TWITTER_REDIRECT_URI}"
        f"&scope=tweet.read%20tweet.write%20users.read%20offline.access"
        f"&state={state_token}"  # Replace with a generated state token for security
        f"&code_challenge={code_challenge}"  # Replace with generated PKCE challenge token
        f"&code_challenge_method=plain"
    )
    return auth_url

def twitter_callback(request):
    """Handles the Twitter callback and exchanges code for an access token."""
    code = request.GET.get('code')
    token_url = "https://api.twitter.com/2/oauth2/token"
    data = {
        "client_id": settings.TWITTER_CLIENT_ID,
        "redirect_uri": settings.TWITTER_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": "challenge_token",  # Should match the code challenge sent earlier
    }
    response = requests.post(token_url, data=data)
    access_token = response.json().get("access_token")

    if not access_token:
        return JsonResponse({"error": "Failed to get access token"}, status=400)

    request.session["twitter_access_token"] = access_token
    return JsonResponse({"message": "Authenticated with Twitter!"})

def twitter_post_tweet(request):
    """Posts a tweet to Twitter on behalf of the user."""
    access_token = request.session.get("twitter_access_token")
    tweet_text = "Hello Twitter from Django!"  # Change to dynamic text as needed

    if not access_token:
        return JsonResponse({"error": "User is not authenticated"}, status=403)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    tweet_url = "https://api.twitter.com/2/tweets"
    data = {
        "text": tweet_text
    }

    response = requests.post(tweet_url, headers=headers, json=data)

    if response.status_code != 201:
        return JsonResponse({"error": "Failed to post tweet"}, status=response.status_code)

    return JsonResponse(response.json())

def twitter_get_replies(request, tweet_id):
    """Retrieves replies to a specific tweet."""
    access_token = request.session.get("twitter_access_token")

    if not access_token:
        return JsonResponse({"error": "User is not authenticated"}, status=403)

    headers = {"Authorization": f"Bearer {access_token}"}
    replies_url = f"https://api.twitter.com/2/tweets/{tweet_id}/conversation"
    response = requests.get(replies_url, headers=headers)

    if response.status_code != 200:
        return JsonResponse({"error": "Failed to fetch replies"}, status=response.status_code)

    return JsonResponse(response.json())

def youtube_auth_link():
    """Generates the YouTube OAuth 2.0 authorization link."""
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "client_secret.json", scopes=settings.YOUTUBE_SCOPES
    )
    flow.redirect_uri = settings.YOUTUBE_REDIRECT_URI

    authorization_url, state = flow.authorization_url(
        access_type="offline",  # For refresh token
        include_granted_scopes="true"
    )

    # request.session["state"] = state
    return authorization_url

def youtube_callback(request):
    """Handles the YouTube callback to exchange the code for an access token."""
    state = request.session["state"]
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "client_secret.json", scopes=settings.YOUTUBE_SCOPES, state=state
    )
    flow.redirect_uri = settings.YOUTUBE_REDIRECT_URI

    authorization_response = request.build_absolute_uri()
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    request.session["youtube_access_token"] = credentials.token
    request.session["youtube_refresh_token"] = credentials.refresh_token
    return JsonResponse({"message": "Authenticated with YouTube!"})

def youtube_upload_video(request):
    """Uploads a video to YouTube."""
    access_token = request.session.get("youtube_access_token")
    video_file_path = "path/to/video.mp4"  # Path to the video file
    title = "My YouTube Video"
    description = "This is a description for my YouTube video."

    credentials = Credentials(token=access_token)
    youtube = build("youtube", "v3", credentials=credentials)

    request_body = {
        "snippet": {
            "title": title,
            "description": description,
            "tags": ["example", "video", "youtube"],
            "categoryId": "22"  # People & Blogs category
        },
        "status": {
            "privacyStatus": "public"
        }
    }

    media_file = MediaFileUpload(video_file_path, chunksize=-1, resumable=True)

    request = youtube.videos().insert(
        part="snippet,status",
        body=request_body,
        media_body=media_file
    )
    response = request.execute()
    return JsonResponse(response)

def youtube_get_comments(request, video_id):
    """Retrieves comments on a specific YouTube video."""
    access_token = request.session.get("youtube_access_token")
    credentials = Credentials(token=access_token)
    youtube = build("youtube", "v3", credentials=credentials)

    request = youtube.commentThreads().list(
        part="snippet",
        videoId=video_id,
        maxResults=20
    )
    response = request.execute()
    return JsonResponse(response)

def google_business_auth_link():
    """Generates the Google Business Profile OAuth 2.0 authorization link."""
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "client_secret.json", scopes=settings.GOOGLE_SCOPES
    )
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI

    authorization_url, state = flow.authorization_url(
        access_type="offline",  # For refresh token
        include_granted_scopes="true"
    )

    # request.session["state"] = state
    return authorization_url

def google_business_callback(request):
    """Handles the Google callback to exchange the code for an access token."""
    state = request.session["state"]
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "client_secret.json", scopes=settings.GOOGLE_SCOPES, state=state
    )
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI

    authorization_response = request.build_absolute_uri()
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    request.session["google_access_token"] = credentials.token
    request.session["google_refresh_token"] = credentials.refresh_token
    return JsonResponse({"message": "Authenticated with Google Business Profile!"})

def google_business_info(request):
    """Fetches the business profile information."""
    access_token = request.session.get("google_access_token")
    credentials = Credentials(token=access_token)
    service = build("mybusinessbusinessinformation", "v1", credentials=credentials)

    account = "accounts/YOUR_ACCOUNT_ID"  # Replace with your Account ID
    response = service.accounts().list().execute()
    return JsonResponse(response)

def create_google_business_post(request):
    """Creates a new post on the business profile."""
    access_token = request.session.get("google_access_token")
    credentials = Credentials(token=access_token)
    service = build("mybusiness", "v4", credentials=credentials)

    # Define the post content
    post_content = {
        "summary": "Check out our new product!",
        "callToAction": {
            "actionType": "LEARN_MORE",
            "url": "https://yourbusiness.com/new-product"
        },
        "media": [
            {
                "mediaFormat": "PHOTO",
                "sourceUrl": "https://yourbusiness.com/image.jpg"
            }
        ]
    }

    location = "locations/YOUR_LOCATION_ID"  # Replace with your Location ID
    response = service.accounts().locations().localPosts().create(
        parent=location,
        body=post_content
    ).execute()

    return JsonResponse(response)
