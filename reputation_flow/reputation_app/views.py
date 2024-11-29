from django.shortcuts import render, redirect
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
import time
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
import praw
import threading
from django.core.files.storage import default_storage
from prawcore.exceptions import ServerError, RequestException, ResponseException


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
ALLOWED_TAGS = ['p', 'b', 'i', 'u', 'strong', 'em', 'a', 'img', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul',
                'li', 'ol', 'br']
ALLOWED_ATTRIBUTES = {
    '*': ['class', 'style'],  # Allow 'class' and 'style' on all tags
    'a': ['href', 'title'],
    'img': ['src', 'alt'],
}
ALLOWED_STYLES = ['color', 'font-weight', 'text-decoration', 'font-style']  # Allowed CSS styles

reddit = praw.Reddit(
    client_id=settings.REDDIT_CLIENT_ID,
    client_secret=settings.REDDIT_CLIENT_SECRET,
    user_agent=settings.REDDIT_USER_AGENT,
    redirect_uri=settings.REDDIT_REDIRECT_URI  # This is required for OAuth2 flows.
)


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
    return render(request, 'index.html')


@api_view(['POST', 'GET'])
def loginUser(request):
    """
    Login page
    """
    print('login request')
    if request.user.is_authenticated:
        # grab the member and their company
        mp = MemberProfile.objects.filter(user=request.user).first()
        print(mp)
        if not mp:
            return render(request, '404error.html')
        cm = CompanyMember.objects.filter(member=mp).first()
        if not cm:
            return render(request, '404error.html')
        user_comp = cm.company.company_id
        return redirect('dashboard', company_id=user_comp)

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
                mp = MemberProfile.objects.filter(user=request.user).first()
                if not mp:
                    return redirect('landing')
                cm = CompanyMember.objects.filter(member=mp).first()
                if not cm:
                    return redirect('landing')
                user_comp = cm.company.company_id
                print(user_comp)
                next_url = f'/b/{user_comp}/dashboard'
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
            comp = Company.objects.filter(company_name=businessName.strip()).exists()
            if comp:
                return Response({'result': False, 'message': 'Company with the provided name already exists'},
                                status.HTTP_200_OK)
            if cpassword != password:
                return Response({'result': False, 'message': 'passwords do not match'},
                                status.HTTP_200_OK)
            if not all([businessName, businessCategory, address1, city, state, country, telephone, postal]):
                return Response({'result': False, 'message': 'Please provide required details'},
                                status.HTTP_200_OK)

            user = User.objects.create_user(username=name.strip(), password=password.strip(), email=email.strip())
            user.save()

            mp = MemberProfile(
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
                city=city,
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
                    'can_modify_ai_assistant': True,
                    'can_update_profile': True,
                    'can_link_unlink_account': True,
                    'can_reply_to_reviews': True,
                    'can_assign_member_review': True,
                    'can_post': True,
                    'can_see_analytics': True,
                    'can_create_team_add_member': True,
                    'can_report_issues_to_Rflow': True
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


def getRedditSubFlairs(cid):
    cm = Company.objects.filter(company_id=cid).first()
    cr = CompanyReddit.objects.filter(company=cm).first()
    reddit_subs = []
    if cr:
        lu=cr.last_updated
        tn=(timezone.now()-lu).total_seconds()
        if tn<3600:
            return
        reddit = praw.Reddit(
            client_id=settings.REDDIT_CLIENT_ID,
            client_secret=settings.REDDIT_CLIENT_SECRET,
            user_agent=settings.REDDIT_USER_AGENT,
            refresh_token=cr.refresh_token,
        )
        for subreddit_name in reddit.user.subreddits(limit=None):
            flair_options = []
            try:
                subreddit = reddit.subreddit(subreddit_name.display_name)
                flair_options = list(subreddit.flair.link_templates)
            except:
                continue
            vl = []
            for f in flair_options:
                if not f['mod_only']:
                    vl.append({
                        'name': f['text'],
                        'id': f['id'],
                        'selected': False
                    })

            present = False
            for sb in cr.subs:
                if sb['sub'] == subreddit_name.display_name:
                    present = True
                    flrs = sb['flairs']
                    pres = False
                    for f in flrs:
                        vaf = [True for d in vl if d['name'] == f['name']]
                        if True in vaf:
                            pres = True
                            break
                    if not pres:
                        sb['flairs'].append(vl)
            cr.last_updated=timezone.now()
            cr.save()
            if not present:
                cr.subs.append(
                    {
                        'sub': subreddit_name.display_name,
                        'flairs': vl
                    }
                )
                cr.save()


@login_required
def dashboard(request, company_id):
    """
    Dashboard displaying the referrals and FAQs
    """
    usr = request.user

    company_id = company_id
    if not company_id:
        return render(request, '404error.html')
    request.session['company_id'] = company_id

    cm = Company.objects.filter(company_id=company_id).first()
    if not cm:
        return render(request, '404error.html')
    mp = MemberProfile.objects.filter(user=usr).first()
    cmp = CompanyMember.objects.filter(member=mp, company=cm).first()
    exp_dif = (cm.company_free_trial_expiry - timezone.now()).days
    cpp = CompanyProfilePicture.objects.filter(company=cm).first()
    sc = CompanyContacts.objects.filter(company=cm).first()
    ctk = CompanyTiktok.objects.filter(company=cm).first()
    cfb = CompanyFacebook.objects.filter(company=cm).first()
    cig = CompanyInstagram.objects.filter(company=cm).first()
    cr = CompanyReddit.objects.filter(company=cm).first()
    if cr:
        sub_f = threading.Thread(target=getRedditSubFlairs, daemon=True, kwargs={'cid': company_id})
        sub_f.start()
    fb_ig = request.session.get('facebook_ig_data', {})
    if fb_ig:
        ldta=fb_ig.get('time_updated')
        ldt=datetime.fromisoformat(ldta)
        df=(timezone.now()-ldt).total_seconds()
        if df > 18000: # update after 6 hrs only
            if cig:
                dt=get_instagram_account_insights(access_token=cig.long_lived_token,instagram_account_id=cig.account_id,company_id=company_id)  
                cig.profile_url=dt['profile_picture_url']  
                fb_ig['time_updated']=timezone.now().isoformat()
                cig.save()
            if cfb:
                dt=get_facebook_page_insights(access_token=cfb.page_access_token,page_id=cfb.page_id,company_id=company_id)
                cfb.profile_url=dt['p_picture']
                fb_ig['time_updated']=timezone.now().isoformat()
                cfb.save()

    else:
        tk_data={
            'time_updated':timezone.now().isoformat()
        }
        if cig:
            dt=get_instagram_account_insights(access_token=cig.long_lived_token,instagram_account_id=cig.account_id,company_id=company_id)  
            cig.profile_url=dt['profile_picture_url']  
            print('saving profile url')
            cig.save()
        if cfb:
            dt=get_facebook_page_insights(access_token=cfb.page_access_token,page_id=cfb.page_id,company_id=company_id)
            cfb.profile_url=dt['p_picture']
            print('saving fb profile pic ')
            cfb.save()
        request.session['facebook_ig_data'] = tk_data
        

    context = {
        'company_name': cm.company_name,
        'company_category': cm.company_category,
        'company_link': cm.company_link,
        # 'company_profile':cpp.p_pic.url if cpp else 'https://pic.onlinewebfonts.com/thumbnails/icons_358304.svg' ,
        'company_profile': 'https://img.freepik.com/premium-vector/vector-logo-dance-club-that-says-dance-club_1107171-3823.jpg',
        'company_about': cm.company_about,
        'company_subs': {
            'subscription_active': cm.company_active_subscription,
            'subscription_type': cm.company_subscription,
            'free_trial': cm.company_free_trial,
            'free_trial_expired': True if exp_dif < 0 else False,
            'free_trial_expiry': exp_dif
        },
        'company_address': {
            'address': cm.company_address,
            'zip': cm.zipcode,
            'city': cm.city,
            'state': cm.state,
            'country': cm.country
        },
        'member_profile': {'role': cmp.role, 'has_admin_priviledges': cmp.is_admin},
        'company_socials': {
            'instagram': sc.instagram if sc else None,
            'facebook': sc.facebook if sc else None,
            'twitter': sc.twitter if sc else None,
            'linkedin': sc.linkedin if sc else None,
            'email': sc.email if sc else None,
            'website': cm.company_website if cm else None,
            'whatsapp': sc.whatsapp if sc else None,
            'phone_number': cm.company_phone if cm else None,
            'youtube': sc.youtube if sc else None,
            'tiktok': sc.tiktok if sc else None,
        },
        'company_id': company_id,
        'user_permissions': {
            'can_modify_ai_assistant': False if not cmp.permissions else cmp.permissions.get('can_modify_ai_assistant',
                                                                                             False),
            'can_update_profile': False if not cmp.permissions else cmp.permissions.get('can_update_profile', False),
            'can_link_unlink_account': False if not cmp.permissions else cmp.permissions.get('can_link_unlink_account',
                                                                                             False),
            # 'can_link_unlink_account':False,
            'can_reply_to_reviews': False if not cmp.permissions else cmp.permissions.get('can_reply_to_reviews',
                                                                                          False),
            'can_assign_member_review': False if not cmp.permissions else cmp.permissions.get(
                'can_assign_member_review', False),
            'can_post': False if not cmp.permissions else cmp.permissions.get('can_post', False),
            'can_see_analytics': False if not cmp.permissions else cmp.permissions.get('can_see_analytics', False),
            'can_create_team_add_member': False if not cmp.permissions else cmp.permissions.get(
                'can_create_team_add_member', False),
            'can_report_issues_to_Rflow': False if not cmp.permissions else cmp.permissions.get(
                'can_report_issues_to_Rflow', False)
        },
        'instagram': {
            'profile': cig.profile_url if cig else '',
            'username': cig.account_name if cig else '',
            'date_linked': cig.date_linked if cig else '',
            'link_url': get_instagram_auth_url(company_id),
            'linked': cig.linked if cig else False,
            'active': cig.active if cig else False
        },
        'facebook': {
            'profile': cfb.profile_url if cfb else '',
            'username': cfb.account_name if cfb else '',
            'date_linked': cfb.date_linked if cfb else '',
            'link_url': get_facebook_auth_url(company_id),
            'linked': cfb.linked if cfb else False,
            'active': cfb.active if cfb else False
        },
        'youtube': {
            'profile': '',
            'username': '',
            'date_linked': '',
            # 'link_url':youtube_auth_link(),
            'linked': False,
            'active': False
        },
        'reddit': {
            'profile': cr.profile_url if cr else '',
            'username': cr.account_username if cr else '',
            'date_linked': '',
            'link_url': reddit_auth_link(company_id),
            'linked': cr.linked if cr else '',
            'active': cr.active if cr else '',
            'comment_karma': cr.comment_karma if cr else '',
            'subs': cr.subs if cr else []
        },
        'tiktok': {
            'profile': ctk.profile_url if ctk else '',
            'username': ctk.account_username if ctk else '',
            'display_name': ctk.account_name if ctk else '',
            'follower_count': ctk.followers_count[-1] if ctk else '-',
            'like_count': ctk.likes_count[-1] if ctk else '-',
            'growth': (ctk.followers_count[-1] - ctk.followers_count[-2]) if ctk and len(
                ctk.followers_count) > 1 else '-',
            'date_linked': ctk.date_linked if ctk else '',
            'link_url': tiktok_auth_link(company_id),
            'linked': ctk.linked if ctk else False,
            'active': ctk.active if ctk else False
        },
        'snapchat': {
            'profile': '',
            'username': '',
            'date_linked': '',
            # 'link_url':tiktok_auth_link(),
            'linked': False,
            'active': False
        },
        'linkedin': {
            'profile': '',
            'username': '',
            'date_linked': '',
            # 'link_url':tiktok_auth_link(company_id),
            'linked': False,
            'active': False
        },
    }
    return render(request, 'dashboard.html', context=context)

@api_view(['POST'])
def fetchPosts(request):
    company_id = request.POST.get('company_id', None)

    if not company_id:
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    cp = CompanyPosts.objects.filter(company=cp).order_by('-pk')
    all_posts = []
    for p in cp:
        um = UploadedMedia.objects.filter(post=p)
        med = []
        for m in um:
            med.append({
                'media_url': m.media.url,
                'is_video': False
            })
        reds=[]
        cover_image_link=''
        
        if 'reddit' in p.platforms:
            cr=CompanyRedditPosts.objects.filter(post_id=p.post_id)
            if cr:
                for c in cr:
                    t_en=0
                    t_com=0
                    for k in c.subs:
                        if k['published']:
                            cover_image_link=k['link']
                            p_id=k['id']
                            submission = reddit.submission(id=p_id)
                            k['upvote_ratio']=submission.upvote_ratio*100
                            k['upvotes']=submission.score
                            k['comments']=submission.num_comments
                            k['crossposts']=submission.num_crossposts
                            reds.append(k)
                            
                            vlx=submission.score+submission.num_comments+submission.num_crossposts
                            t_en+=vlx
                            t_com+=submission.num_comments
                    p.comment_count=t_com
                    p.engagement_count=t_en
                    p.save()   
                    c.save()    
                            
        eng_cnt=p.engagement_count
        if eng_cnt>1000000:
            eng_cnt=round(eng_cnt/1000000,1)
        elif eng_cnt>1000:
            eng_cnt=round(eng_cnt/1000,1)
        cmt_cnt=p.comment_count
        if cmt_cnt>1000:
            cmt_cnt=round(cmt_cnt/1000,1)
        elif cmt_cnt>1000:
            cmt_cnt=round(cmt_cnt/1000,1)
        all_posts.append({
            'platforms': [pl.capitalize() for pl in p.platforms],
            'title': p.title,
            'content': p.description,
            'is_uploaded': p.is_published,
            'is_scheduled': p.is_scheduled,
            'comment_count':cmt_cnt,
            'engagement_count':eng_cnt,
            'tags': [] if not p.tags else p.tags.split(),
            'has_media': p.has_media,
            'cover_image_link':cover_image_link,
            'media':None if not p.has_media else UploadedMedia.objects.filter(post=p).first(),
            'date_uploaded': p.date_uploaded,
            'date_scheduled':p.date_scheduled,
            'media': med,
            'post_id':p.post_id,
            'has_all':len(p.platforms)==4,
            'has_reddit':'reddit' in p.platforms,
            'has_tiktok':'tiktok' in p.platforms,
            'has_facebook':'facebook' in p.platforms,
            'has_instagram':'instagram' in p.platforms,

        })
    context = {
        'posts': all_posts,
    }
    return render(request, 'dashboard.html', context=context)

# retrieve the stats of a given post
@api_view(['POST'])
def getStats(request):
    post_id = request.POST.get('post_id', None)
    if not post_id:
        return Response({'error': 'Bad request'})
    # get the ost from the post_id
    pst=CompanyPosts.objects.filter(post_id=post_id).first()
    if not pst:
        return Response({'error': 'Bad request'})
    

    my_dict = {'Facebook': 270, 'Instagram':80, 'Tiktok': 30, 'Reddit': 830}
    sorted_dict = dict(sorted(my_dict.items(), key=lambda item: item[1], reverse=True))
    ptfrms=[]
    ptfrms_en=[]
    cr = CompanyRedditPosts.objects.filter(post_id=post_id).first()
    red_up=[]
    red_cmt=[]
    red_cpst=[]
    red_tteng=[]
    red_subs=[]
    for c in cr.subs:
        k=c
        if k['published']:
            p_id=k['id']
            submission = reddit.submission(id=p_id)
            k['upvote_ratio']=submission.upvote_ratio*100
            k['upvotes']=submission.score
            k['comments']=submission.num_comments
            k['crossposts']=submission.num_crossposts
            red_subs.append(f"r/{k['sub_name']}")
            
            # vlx=submission.score+submission.num_comments+submission.num_crossposts
            # t_en+=vlx
            # t_com+=submission.num_comments
        
        red_up.append(c['upvotes'])
        red_tteng.append(c['upvote_ratio'])
        red_cmt.append(c['comments'])
        red_cpst.append(c['crossposts'])
    print(red_up)
    red_te=0
    if red_tteng:
        red_te=sum(red_tteng)/len(red_tteng) 
    return Response({'result': 'success',
                     'has_reddit':True,
                     'reddit_total_engagement':f'{red_te}%',
                     'reddit_upvotes':red_up,
                     'reddit_comments':red_cmt,
                     'reddit_crossposts':red_cpst,
                     'reddit_subs':red_subs,
                     'platform_engagement':ptfrms_en,
                     'pltfrms':ptfrms 
                     })
    
@api_view(['POST'])
def fetchTeams(request):
    company_id = request.POST.get('company_id', None)

    if not company_id:
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    mp = MemberProfile.objects.filter(user=request.user).first()
    cmp = CompanyMember.objects.filter(member=mp, company=cp).first()
    cmp = CompanyMember.objects.filter(member=mp, company=cp).first()

    context = {
        'user_permissions': {
            'can_modify_ai_assistant': False if not cmp.permissions else cmp.permissions.get('can_modify_ai_assistant',
                                                                                             False),
            'can_update_profile': False if not cmp.permissions else cmp.permissions.get('can_update_profile', False),
            'can_link_unlink_account': False if not cmp.permissions else cmp.permissions.get('can_link_unlink_account',
                                                                                             False),
            'can_reply_to_reviews': False if not cmp.permissions else cmp.permissions.get('can_reply_to_reviews',
                                                                                          False),
            'can_assign_member_review': False if not cmp.permissions else cmp.permissions.get(
                'can_assign_member_review', False),
            'can_post': False if not cmp.permissions else cmp.permissions.get('can_post', False),
            'can_see_analytics': False if not cmp.permissions else cmp.permissions.get('can_see_analytics', False),
            'can_create_team_add_member': False if not cmp.permissions else cmp.permissions.get(
                'can_create_team_add_member', False),
            'can_report_issues_to_Rflow': False if not cmp.permissions else cmp.permissions.get(
                'can_report_issues_to_Rflow', False)
        },
        'all_teams': CompanyTeam.objects.filter(company=cp).order_by('-pk'),
    }
    return render(request, 'dashboard.html', context=context)


#  create team
@login_required
@api_view(['POST'])
def createTeam(request):
    company_id = request.POST.get('company_id', None)
    team_name = request.POST.get('team_name', None)
    team_about = request.POST.get('team_about', None)
    mp = MemberProfile.objects.filter(user=request.user).first()
    if not mp:
        return Response({'error': 'Forbidden'})
    if not all([company_id, team_name, team_about]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    ct = CompanyTeam.objects.filter(company=cp, team_name=team_name).first()
    if ct:
        return Response({'error': 'Team with similar name already exist'})
    ct = CompanyTeam(
        company=cp,
        team_name=team_name,
        team_about=team_about
    )

    ct.save()
    ct.members.add(mp)
    ct.save()
    mp = MemberProfile.objects.filter(user=request.user).first()
    cmp = CompanyMember.objects.filter(member=mp, company=cp).first()

    context = {
        'user_permissions': {
            'can_modify_ai_assistant': False if not cmp.permissions else cmp.permissions.get('can_modify_ai_assistant',
                                                                                             False),
            'can_update_profile': False if not cmp.permissions else cmp.permissions.get('can_update_profile', False),
            'can_link_unlink_account': False if not cmp.permissions else cmp.permissions.get('can_link_unlink_account',
                                                                                             False),
            'can_reply_to_reviews': False if not cmp.permissions else cmp.permissions.get('can_reply_to_reviews',
                                                                                          False),
            'can_assign_member_review': False if not cmp.permissions else cmp.permissions.get(
                'can_assign_member_review', False),
            'can_post': False if not cmp.permissions else cmp.permissions.get('can_post', False),
            'can_see_analytics': False if not cmp.permissions else cmp.permissions.get('can_see_analytics', False),
            'can_create_team_add_member': False if not cmp.permissions else cmp.permissions.get(
                'can_create_team_add_member', False),
            'can_report_issues_to_Rflow': False if not cmp.permissions else cmp.permissions.get(
                'can_report_issues_to_Rflow', False)
        },
        'all_teams': CompanyTeam.objects.filter(company=cp).order_by('-pk'),
        'invite_links': CompanyTeamInviteLinks.objects.filter(team=ct).order_by('-pk')
    }
    return render(request, 'dashboard.html', context=context)


# delete team 
@api_view(['POST'])
def deleteTeam(request):
    company_id = request.POST.get('company_id', None)
    team_id = request.POST.get('team_id', None)
    if not all([company_id, team_id]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    ct = CompanyTeam.objects.filter(company=cp, id=team_id).first()
    if not ct:
        return Response({'error': 'Bad request'})
    ct.delete()
    mp = MemberProfile.objects.filter(user=request.user).first()
    cmp = CompanyMember.objects.filter(member=mp, company=cp).first()
    cmp = CompanyMember.objects.filter(member=mp, company=cp).first()

    context = {
        'user_permissions': {
            'can_modify_ai_assistant': False if not cmp.permissions else cmp.permissions.get('can_modify_ai_assistant',
                                                                                             False),
            'can_update_profile': False if not cmp.permissions else cmp.permissions.get('can_update_profile', False),
            'can_link_unlink_account': False if not cmp.permissions else cmp.permissions.get('can_link_unlink_account',
                                                                                             False),
            'can_reply_to_reviews': False if not cmp.permissions else cmp.permissions.get('can_reply_to_reviews',
                                                                                          False),
            'can_assign_member_review': False if not cmp.permissions else cmp.permissions.get(
                'can_assign_member_review', False),
            'can_post': False if not cmp.permissions else cmp.permissions.get('can_post', False),
            'can_see_analytics': False if not cmp.permissions else cmp.permissions.get('can_see_analytics', False),
            'can_create_team_add_member': False if not cmp.permissions else cmp.permissions.get(
                'can_create_team_add_member', False),
            'can_report_issues_to_Rflow': False if not cmp.permissions else cmp.permissions.get(
                'can_report_issues_to_Rflow', False)
        },
        'all_teams': CompanyTeam.objects.filter(company=cp).order_by('-pk'),
        'invite_links': CompanyTeamInviteLinks.objects.filter(team=ct).order_by('-pk')

    }
    return render(request, 'dashboard.html', context=context)


# get team 
@api_view(['POST'])
def viewTeam(request):
    company_id = request.POST.get('company_id', None)
    team_id = request.POST.get('team_id', None)
    if not all([company_id, team_id]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    ct = CompanyTeam.objects.filter(company=cp, id=team_id).first()
    if not ct:
        return Response({'error': 'Bad request'})
    mp = MemberProfile.objects.filter(user=request.user).first()
    cmp = CompanyMember.objects.filter(member=mp, company=cp).first()

    chat_messages = []
    for cm in CompanyTeamChat.objects.filter(team=ct):
        prf = MemberPP.objects.filter(member=mp).first()
        chat_messages.append(
            {
                'me': True if cm.sender == mp else False,
                'dp': prf.pic.url if prf else None,
                'sender': cm.sender,
                'message': cm.message,
                'date_sent': cm.date_sent.strftime('%m/%y %H:%M')
            }
        )

    t_mem = []
    for r in ct.members.all():
        profile_pic = MemberPP.objects.filter(member=r).first()
        t_mem.append(
            {'name': r.user.username,
             'profile_pic': profile_pic.pic if profile_pic else None
             }
        )
    t_actv = []
    for t_a in CompanyTeamActivity.objects.filter(team=ct).order_by('-pk'):
        tm_bef = (timezone.now - t_a.date_created)
        ti_b = ''
        if tm_bef < 86400:
            ti_b = tm_bef // 3600  # how many hours ago
            ti_b = ti_b + ' hours ago'
            if ti_b < 0:
                ti_b = tm_bef // 60  # how many minutes ago
                ti_b = ti_b + ' minutes ago'
        t_actv.append(
            {
                'title': t_a.title,
                'time_from': t_a.date_created,
                'date_created': ti_b,
            }
        )

    context = {
        'user_permissions': {
            'can_modify_ai_assistant': False if not cmp.permissions else cmp.permissions.get('can_modify_ai_assistant',
                                                                                             False),
            'can_update_profile': False if not cmp.permissions else cmp.permissions.get('can_update_profile', False),
            'can_link_unlink_account': False if not cmp.permissions else cmp.permissions.get('can_link_unlink_account',
                                                                                             False),
            'can_reply_to_reviews': False if not cmp.permissions else cmp.permissions.get('can_reply_to_reviews',
                                                                                          False),
            'can_assign_member_review': False if not cmp.permissions else cmp.permissions.get(
                'can_assign_member_review', False),
            'can_post': False if not cmp.permissions else cmp.permissions.get('can_post', False),
            'can_see_analytics': False if not cmp.permissions else cmp.permissions.get('can_see_analytics', False),
            'can_create_team_add_member': False if not cmp.permissions else cmp.permissions.get(
                'can_create_team_add_member', False),
            'can_report_issues_to_Rflow': False if not cmp.permissions else cmp.permissions.get(
                'can_report_issues_to_Rflow', False)
        },
        'team': ct,
        'all_teams': CompanyTeam.objects.filter(company=cp).order_by('-pk'),
        'invite_links': CompanyTeamInviteLinks.objects.filter(team=ct).order_by('-pk'),
        'team_members': t_mem,
        'team_files': CompanyTeamFiles.objects.filter(team=ct).order_by('-pk'),
        'announcements': CompanyTeamAnnouncements.objects.filter(team=ct).order_by('-pk'),
        'activities': t_actv,
        'chat_messages': chat_messages

    }
    return render(request, 'dashboard.html', context=context)


# create invite link
@api_view(['POST'])
def generateInviteLink(request):
    company_id = request.POST.get('company_id', None)
    team_id = request.POST.get('team_id', None)
    members_num = request.POST.get('members_number', None)
    members_perm = request.POST.get('members_permissions', None)
    if not all([company_id, team_id, members_num, members_perm]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    ct = CompanyTeam.objects.filter(company=cp, id=team_id).first()
    if not ct:
        return Response({'error': 'Bad request'})
    print(members_perm)
    permissions = members_perm.split(',')
    cleaned_permissions = [permission.strip().replace('\r', '').replace('\n', ' ') for permission in permissions]
    uid = uuid.uuid4()
    url_link = f'https://www.revflow.co/invite/{uid}'

    # save the link
    cil = CompanyTeamInviteLinks(
        team=ct,
        link=url_link,
        permissions=cleaned_permissions,
        max_members=members_num
    )
    cil.save()

    return Response({'result': url_link})

# get team 
@api_view(['POST'])
def sendChat(request):
    company_id = request.POST.get('company_id', None)
    team_id = request.POST.get('team_id', None)
    message = request.POST.get('message', None)
    if not all([message, team_id, company_id]):
        return Response({'error': 'Bad request'})
    usr = MemberProfile.objects.filter(user=request.user).first()
    if not usr:
        return Response({'error': 'Bad request'})
    ct = CompanyTeam.objects.filter(id=team_id).first()
    if not ct:
        return Response({'error': 'Bad request'})
    # check if user is part of the team
    if not ct.members.filter(id=usr.id).exists():
        print('member dont exist')

        return Response({'error': 'Bad request'})
    ctc = CompanyTeamChat(
        team=ct,
        sender=usr,
        message=message,
    )
    ctc.save()
    chat_messages = []
    for cm in CompanyTeamChat.objects.filter(team=ct):
        prf = MemberPP.objects.filter(member=usr).first()
        chat_messages.append(
            {
                'me': True if cm.sender == usr else False,
                'dp': prf.pic.url if prf else None,
                'sender': cm.sender,
                'message': cm.message,
                'date_sent': cm.date_sent.strftime('%m/%y %H:%M')
            }
        )
    context = {
        'chat_messages': chat_messages
    }
    return render(request, 'dashboard.html', context=context)

@api_view(['POST'])
def gettiktokCreatorInfo(request):
    company_id = request.POST.get('company_id', None)
    if not all([company_id]):
        return Response({'error': 'Tiktok Bad request '})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Tiktok Bad request'})
    ctk=CompanyTiktok.objects.filter(company=cp).first()
    if not ctk:
        return Response({'error': 'TikTok Bad request.Try again or remove TikTok '})
    sess = request.session.get('tiktok_creator_info', {})
    if sess:
        ldta=sess.get('time_updated')
        ldt=datetime.fromisoformat(ldta)
        df=(timezone.now()-ldt).total_seconds()
        dur=sess.get('max_video_post_duration_sec')
        if df < 86400 and dur != None: # update after 24 hr only
            return Response({
                'max_video_post_duration_sec':sess.get('max_video_post_duration_sec'),
                'stitch_disabled':sess.get('stitch_disabled'),
                'comment_disabled':sess.get('comment_disabled'),
                'duet_disabled':sess.get('duet_disabled')
            }) 

        
    try:
        url = "https://open.tiktokapis.com/v2/post/publish/creator_info/query/"
        headers = {
            "Authorization": f"Bearer {ctk.access_token}",
            "Content-Type": "application/json"
        }

        response = requests.post(url, headers=headers,verify=False)
        res=response.json().get('data')
        tk_data={
            'max_video_post_duration_sec':res.get('max_video_post_duration_sec'),
            'stitch_disabled':res.get('stitch_disabled'),
            'comment_disabled':res.get('comment_disabled'),
            'duet_disabled':res.get('duet_disabled'),
            'time_updated':timezone.now().isoformat()
        }
        request.session['tiktok_creator_info'] = tk_data
        return Response({
            'max_video_post_duration_sec':res.get('max_video_post_duration_sec'),
            'stitch_disabled':res.get('stitch_disabled'),
            'comment_disabled':res.get('comment_disabled'),
            'duet_disabled':res.get('duet_disabled')
        }) 
    except:
        return Response({'error': 'TikTok Bad request.Try again or remove TikTok '})

def postTiktok(company,description,video,duet,comment,stitch,audience,post_id,mentions):
    """
    Initialize a chunked video upload to TikTok.
    """
    ctk=CompanyTiktok.objects.filter(company=company).first()
    if not ctk:
        return 'No Company Tiktok'
    access_token=ctk.access_token
    video_size=video['file_size']
    # Get the necessary data from the request
    chunk_size = 20* 1024 * 1024  # 10 MB in bytes

    # Adjust chunk size if the video is smaller than the chunk size
    if video_size < chunk_size:
        chunk_size = video_size  
        total_chunk_count=1
    if video_size > chunk_size:
        total_chunk_count=4
        chunk_size = int(video_size/4)
         
    
    url = "https://open.tiktokapis.com/v2/post/publish/creator_info/query/"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    response = requests.post(url, headers=headers)
    # API URL for the video upload initialization
    url = "https://open.tiktokapis.com/v2/post/publish/video/init/"
    # Prepare the headers with the access token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # Prepare the JSON payload
    payload = {
        "post_info": {
            "title": description,  
            "privacy_level": audience,   
            "disable_duet": not duet,
            "disable_comment": not comment,
            "disable_stitch": not stitch
        },
        "source_info": {
            "source": "FILE_UPLOAD",
            "video_size": video_size,     
            "chunk_size": chunk_size,     
            "total_chunk_count": total_chunk_count  
        }
    }

    # Make the POST request
    response = requests.post(url, headers=headers, json=payload)
    # Check the response status and print the result
    if response.status_code == 200:
        print("Upload initialized successfully.")
    else:
        print(f"Error: {response.status_code}")
        print(response.json())

        return
        

    # Parse the response
    upload_data = response.json()
    publish_id = upload_data.get('data', {}).get('publish_id')
    chunk_upload_url = upload_data.get('data', {}).get('upload_url')

    if not all([publish_id, chunk_upload_url]):
        return print({'error': 'Missing publish_id or upload_url in response'})

    try:
        with open(video['image_path'], "rb") as video_file:
            video_data = video_file.read()
            total_size = len(video_data)

            upload_headers = {
                "Content-Range": f"bytes 0-{total_size - 1}/{total_size}",
                "Content-Type": "video/mp4"
            }

            upload_response = requests.put(chunk_upload_url, headers=upload_headers, data=video_data)

            if upload_response.status_code == 201:
                print("Video uploaded successfully!")

            else:
                print(f"Failed to upload video: {upload_response.status_code}")
                print(upload_response.json())
                return

            #wait for the video to be published
            published=False
            # Define the API endpoint and access token
            url = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

            # Prepare the payload with the publish ID
            data = {
                "publish_id": publish_id  # Replace with your actual publish ID
            }

            # Send the request
            content_status = "PROCESSING_UPLOAD"
            while content_status == "PROCESSING_UPLOAD":
                response = requests.post(url, headers=headers, json=data,verify=False)
                if response.status_code == 200:
                    status = response.json()
                    content_status = status.get("data", {}).get("status", "Unknown")
                    print('processing status',content_status)
                    if content_status == "PUBLISH_COMPLETE":
                        published=True
                time.sleep(10)
        
            # get latest updated video
            if published:
                video_list_url = "https://open.tiktokapis.com/v2/video/list/?fields=id,cover_image_url,video_url"
                payload = {
                    "max_count": 5,
                }

                # Make the POST request
                response = requests.post(video_list_url, headers=headers, data=json.dumps(payload),verify=False)
                videos = response.json()['data']
                print(videos)
                # Display the list of videos
                video_id=videos['videos'][0]['id']
                video_cover=videos['videos'][0]['cover_image_url']
                video_link=videos['videos'][0]['video_url']
                # save the tiktok post
                ctkp=CompanyTiktokPosts(
                    post_id=post_id,
                    video_id=video_id,
                    is_published=published,
                    mentions=mentions,
                    cover_image_url=video_cover,
                    post_link=video_link,
                )
                ctkp.save()
                return print({
                    'message': 'Video uploaded successfully',
                })
            else:
                ctkp=CompanyTiktokPosts(
                    post_id=post_id,
                    is_published=published,
                )
                ctkp.save()
            
    except Exception as e:
        return print({'error': 'An unexpected error occurred', 'details': str(e)})


def postInstagram(account_id,media,access_token,description,has_media,post_id,to_stories,to_post,to_reels):
    if not has_media:
        return
    # upload the media to s3 bucket
    for m in media:
        pass
    print('the ltc')
    print(len(media))
    print()
    return
    # retrieve the media urls
    media_urls = [
    "https://example.com/image1.jpg",
    "https://example.com/image2.jpg",
    "https://example.com/video1.mp4"
        ]
    # post the media to instagram
    is_carousel=False
    if len(media_urls)>1:
        is_carousel=True    
    if is_carousel:
        # Step 1: Upload each media item individually and collect their media_ids
        media_ids = []
        for url in media_urls:
            payload = {
                "image_url" if url.endswith(".jpg") or url.endswith(".png") else "video_url": url,
                "is_carousel_item": "true",
                "access_token": access_token
            }
            response = requests.post(f"https://graph.facebook.com/v21.0/{account_id}/media", data=payload)
            
            if response.status_code == 200:
                media_id = response.json().get("id")
                media_ids.append(media_id)
                print(f"Uploaded media successfully. Media ID: {media_id}")
            else:
                print(f"Error uploading media: {response.json()}")
                exit()

        # Step 2: Create the carousel container
        carousel_payload = {
            "children": ",".join(media_ids),  # Media IDs must be comma-separated
            "caption": description,
            "access_token": access_token
        }
        carousel_response = requests.post(f"https://graph.facebook.com/v21.0/{account_id}/media", data=carousel_payload)

        if carousel_response.status_code == 200:
            creation_id = carousel_response.json().get("id")
            print(f"Carousel container created successfully. Creation ID: {creation_id}")
        else:
            print(f"Error creating carousel container: {carousel_response.json()}")
            exit()
    else:    
        # delete the media from s3 bucket to free storage
        url = f"https://graph.facebook.com/v21.0/{account_id}/media"
        isImage=True 
        if media[0]['content_type'].startswith("video/"):
            isImage=False
        payload = {
            "image_url" if isImage else "video_url": media_urls[0],
            "caption": description, 
            "access_token": access_token,
        }
        if not isImage and to_reels:
            payload['media_type']=='REELS'
            response = requests.post(url, data=payload)

        if to_stories:
            payload['media_type']=='STORIES'
        response = requests.post(url, data=payload)

        if response.status_code == 200:
            creation_id = response.json().get("id")
            print(f"Media uploaded successfully! Media ID: {creation_id}")
        else:
            print(f"Error: {response.json()}")
            return
    # Step 3: Publish the carousel post
    publish_payload = {
        "creation_id": creation_id,
        "access_token": access_token
    }
    publish_response = requests.post(f"https://graph.facebook.com/v16.0/{account_id}/media_publish", data=publish_payload)

    if publish_response.status_code == 200:
        post_id = publish_response.json().get("id")
        print(f"post published successfully! Post ID: {post_id}")
    else:
        print(f"Error publishing carousel post: {publish_response.json()}")
        
        
def postFacebook(page_id,media,access_token,title,description,is_video,has_media,post_id,to_stories,to_post):
    # API endpoint for creating a post
    url = f"https://graph.facebook.com/v21.0/{page_id}/feed"
    
    # save video post
    cfb_pst=CompanyFacebookPosts(
        post_id=post_id,
        to_stories=to_stories,
        to_posts=to_post,
    )
    cfb_pst.save()
    if is_video:
        # API URL for video uploads
        url = f"https://graph-video.facebook.com/v21.0/{page_id}/videos"
        
        # Payload for video upload
        payload = {
            "title": title,
            "description": description,
            "access_token": access_token
        }

        # Path to the video file
        video_file_path = media[0]['image_path']
        if to_post:
            # Open the video file and send the POST request
            with open(video_file_path, "rb") as video_file:
                files = {
                    "source": video_file
                }
                response = requests.post(url, data=payload, files=files)

            # Handle the response
            if response.status_code == 200:
                video_id=response.json().get('id')
                cfb_pst.content_id=video_id
                cfb_pst.is_published=True
                cfb_pst.save()
                print(response.json())
                print("Video uploaded successfully!")
            else:
                print(f"Error uploading video: {response.status_code}")
                print(response.json())
        # check if uploading to stories
        if to_stories:
            print('attempting to upload video to stories')
            # initialise upload 
            url = f"https://graph.facebook.com/v21.0/{page_id}/video_stories"
            payload={
                "upload_phase":"start",
                "access_token": access_token
            }
            response = requests.post(url,data=payload)
            if response.status_code == 200:
                video_id=response.json().get('video_id')
                upload_url=response.json().get('upload_url')
                print('initialisation successful, ',upload_url)
                
            else:
                print(f"Error uploading video: {response.status_code}")
                print(response.json())
                return
            
            # Open the video file in binary mode
            with open(media[0]['image_path'], "rb") as video_file:
                # Make the POST request
                # Headers
                headers = {
                    "offset": "0",  # Start uploading from the beginning
                    "Authorization": f"OAuth {access_token}",
                    "file_size": str(media[0]['file_size']) , # File size in bytes
                }
                files = {
                    "source": video_file
                }

                print('attempting to upload',upload_url)
                response = requests.post(upload_url, headers=headers, data=files)
                print(response.json())    
                # response = requests.post(url, headers=headers, data=video_file)

            # Handle the response
            if response.status_code == 200:
                # check upload status
                p_phse = 'not_started'
                while p_phse == 'not_started':
                    status_url = f"https://graph.facebook.com/v21.0/{video_id}"
                    status_payload = {
                        "fields": "status",
                        "access_token": access_token,
                    }
                    status_response = requests.get(status_url, params=status_payload)
                    status_data = status_response.json()

                    # Inspect status response
                    p_phse=status_data.get('status').get('processing_phase').get('status')
                    u_phse=status_data.get('status').get('publishing_phase').get('status')
                    cright=status_data.get('status').get('copyright_check_status').get('status')
                    if cright == 'error':
                        print('Video did not pass copyright check')
                        break
                    print(status_data)
                    print()
                    time.sleep(10)
                
                # finish upload
                url = f"https://graph.facebook.com/v21.0/{page_id}/video_stories"
                payload = {
                    "video_id": video_id,
                    "upload_phase": "finish",
                    "access_token": access_token,
                }
                response = requests.post(url, data=payload)
                print(response.json())
                content_id=response.json().get('id')
                cfb_pst.content_id=content_id
                cfb_pst.is_published=True
                cfb_pst.save()
                print("Video uploaded successfully!")
                cfbp=CompanyFacebookPosts(
                    
                )
            else:
                print(f"Error uploading video: {response.status_code}")
                print(response.json())
        return

    if has_media:
        photo_paths = [md['image_path'] for md in media]

        # Step 1: Upload photos to get attachment IDs
        photo_ids = []
        photo_upload_url = f"https://graph.facebook.com/v21.0/{page_id}/photos"
        
        # check pages managed by users
        for photo_path in photo_paths:
            with open(photo_path, "rb") as photo:
                # Upload each photo to get an ID
                payload = {"published": "false", "access_token": access_token}  # Set 'published' to false
                files = {"source": photo}
                response = requests.post(photo_upload_url, data=payload, files=files)

                if response.status_code == 200:
                    photo_id = response.json().get("id")
                    photo_ids.append({"media_fbid": photo_id})
                else:
                    print(f"Error uploading {photo_path}: {response.json()}")
        # Step 2: Create a post with all photo IDs
        if photo_ids:
            # Prepare the payload for the post
            payload = {
                "message": f'{description}',
                "attached_media": photo_ids,
                "access_token": access_token
            }
            # Make the POST request to create the post
            if to_post:
                response = requests.post(url,json=payload)

                if response.status_code == 200:
                    content_id=response.json().get('id')
                    cfb_pst.content_id=content_id
                    cfb_pst.is_published=True
                    cfb_pst.save()
                    print("Post created successfully with multiple photos!")
                    print(response.json())
                else:
                    print(f"Error creating post: {response.status_code}")
                    print(response.json())

            # check if user is uploading to stories
            if to_stories:
                print('attempting to upload photo(s) to stories')
                for ph_id in photo_ids:
                    url = f"https://graph.facebook.com/v21.0/{page_id}/photo_stories"
                    payload = {
                        "photo_id":ph_id['media_fbid'],
                        "access_token": access_token
                    }
                # Make the POST request to create the post
                    response = requests.post(url,json=payload)

                if response.status_code == 200:
                    content_id=response.json().get('id')
                    cfb_pst.content_id=content_id
                    cfb_pst.is_published=True
                    cfb_pst.save()
                    print("stories created successfully with multiple photos!")
                    print(response.json())
                else:
                    print(f"Error creating post: {response.status_code}")
                    print(response.json())
        else:
            print("No photos were successfully uploaded.")
    else:
        if to_post:
            url = f"https://graph.facebook.com/v21.0/{page_id}/feed"

            payload = {
                "message": description,
                "access_token": access_token,
            }

            response = requests.post(url, data=payload)

            if response.status_code == 200:
                print("Link post created successfully!")
                content_id=response.json().get('id')
                cfb_pst.content_id=content_id
                cfb_pst.is_published=True
                cfb_pst.save()
                print(response.json())
            else:
                print(f"Error creating post: {response.status_code}")
                print(response.json())

def postReddit(title,description,subs,hasMedia,files,nsfw_tag,spoiler_tag,red_refresh_token,post_id,company):
    cr=CompanyReddit.objects.filter(company=company).first()
    reddit = praw.Reddit(
            client_id=settings.REDDIT_CLIENT_ID,
            client_secret=settings.REDDIT_CLIENT_SECRET,
            user_agent=settings.REDDIT_USER_AGENT,
            refresh_token=red_refresh_token,
        )
    sub_tr=[]
    for s in subs:
        for cs in cr.subs:
            sb=s.split('r/')[-1]
            default_flair=''
            if sb==cs['sub']:
                for fl in cs['flairs']:
                    if fl['selected']:
                        default_flair=fl['id']
                        break
                # upload the post
                subreddit = reddit.subreddit(sb)
                if hasMedia:
                    # upload with media
                    if len(files)==1:
                        # check if image or video and upload accoordingly
                        print('single file',files[0]['content_type'])
                        f=files[0]['image_path']
                        content_type=files[0]['content_type']
                        if content_type.startswith("image/"):
                            print('submitting image')
                            try:
                                submission = subreddit.submit_image(
                                    title=title,
                                    image_path=f,
                                    flair_id=default_flair,
                                    timeout=30,
                                    nsfw=nsfw_tag,
                                    spoiler=spoiler_tag

                                )
                                sub_tr.append({
                                    'sub_name':sb,
                                    'id':submission.id,
                                    'link':submission.url,
                                    'permalink':f"https://www.reddit.com{submission.permalink}",
                                    'published':True,
                                    'result':'Submission was accepted',
                                    'upvotes':0,
                                    'comments':0,
                                    'upvote_ratio':0,
                                    'crossposts':0
                                })
                                default_storage.delete(files[0]['image_path'])
                            except Exception as e:
                                sub_tr.append({
                                    'sub_name':sb,
                                    'id':'',
                                    'link':'',
                                    'published':False,
                                    'result':e,
                                    'comments':0,
                                    'upvotes':0,
                                    'upvote_ratio':0,
                                    'crossposts':0
                                })
                            cr.save()
                        elif content_type.startswith("video/"):
                            print('submitting video')
                            try:
                                submission = subreddit.submit_video(
                                    title=title,
                                    video_path=f,
                                    timeout=30,
                                    nsfw=nsfw_tag,
                                    spoiler=spoiler_tag

                                )
                                print(f"Video post created successfully: {submission.url}")
                                sub_tr.append({
                                    'sub_name':sb,
                                    'id':submission.id,
                                    'link':submission.url,
                                    'permalink':f"https://www.reddit.com{submission.permalink}",
                                    'published':True,
                                    'result':'Submission was accepted',
                                    'comments':0,
                                    'upvotes':0,
                                    'upvote_ratio':0,
                                    'crossposts':0
                                })
                                default_storage.delete(files[0]['image_path'])
                            except Exception as e:
                                sub_tr.append({
                                    'sub_name':sb,
                                    'id':'',
                                    'link':'',
                                    'published':False,
                                    'result':e,
                                    'comments':0,
                                    'upvotes':0,
                                    'upvote_ratio':0,
                                    'crossposts':0
                                })
                            cr.save()
                        else:
                            sub_tr.append({
                                    'sub_name':sb,
                                    'id':'',
                                    'link':'',
                                    'published':False,
                                    'result':'Unable to submit post',
                                    'comments':0,
                                    'upvotes':0,
                                    'upvote_ratio':0,
                                    'crossposts':0
                                })
                            cr.save()
                            default_storage.delete(files[0]['image_path'])
                    else:
                        # # Submit a gallery post
                        try:
                            submission = subreddit.submit_gallery(
                                title=title,
                                images=files,
                                flair_id=default_flair,
                                timeout=30,
                                nsfw=nsfw_tag,
                                spoiler=spoiler_tag

                            )
                            # clear the respective temporary files
                            sub_tr.append({
                                'sub_name':sb,
                                'id':submission.id,
                                'link':submission.url,
                                'permalink':f"https://www.reddit.com{submission.permalink}",
                                'published':True,
                                'result':'Submission was accepted',
                                'comments':0,
                                'upvotes':0,
                                'upvote_ratio':0,
                                'crossposts':0
                            })
                            for f in files:
                                default_storage.delete(f['image_path'])
                        except Exception as e:
                            sub_tr.append({
                                'sub_name':sb,
                                'id':'',
                                'link':'',
                                'published':False,
                                'result':e,
                                'comments':0,
                                'upvotes':0,
                                'upvote_ratio':0,
                                'crossposts':0
                            })
                        cr.save()

                else:
                    submission = subreddit.submit(
                        title, 
                        selftext=description,
                        flair_id=default_flair, 
                        nsfw=nsfw_tag,
                        spoiler=spoiler_tag)
                    sub_tr.append({
                        'sub_name':sb,
                        'id':submission.id,
                        'link':submission.url,
                        'permalink':f"https://www.reddit.com{submission.permalink}",
                        'published':True,
                        'result':'Submission was accepted',
                        'comments':0,
                        'upvotes':0,
                        'upvote':0,
                        'upvote_ratio':0,
                        'crossposts':0
                    })
    
                break
        # get the selected flairs

        # subreddit = reddit.subreddit('test')
        # # Submit the post to the chosen subreddit
        # post = subreddit.submit(title, selftext=description)
    cred = CompanyRedditPosts(
        post_id=post_id,
        nsfw_tag=nsfw_tag,
        spoiler_flag=spoiler_tag,
        target_subs=subs,
        subs=sub_tr,
    )
    cred.save()

    print('post has been updated')

@api_view(['POST'])
def uploadPost(request):
    company_id = request.POST.get('company_id', None)
    title = request.POST.get('title', None)
    description = request.POST.get('description', None)

    # Platform selected
    instagramSelected = request.POST.get('instagramSelected', 'false').lower() == 'true'
    facebookSelected = request.POST.get('facebookSelected', 'false').lower() == 'true'
    tiktokSelected = request.POST.get('tiktokSelected', 'false').lower() == 'true'
    redditSelected = request.POST.get('redditSelected', 'false').lower() == 'true'

    isScheduled = request.POST.get('isScheduled', 'false').lower() == 'true'
    hasMedia = request.POST.get('hasMedia', 'false').lower() == 'true'
    hashTags = request.POST.get('hashTags', None)

    # Tiktok
    tk_allow_comment = request.POST.get('tk_allow_comment', 'false').lower() == 'true'
    tk_allow_duet = request.POST.get('tk_allow_duet', 'false').lower() == 'true'
    tk_allow_stitch = request.POST.get('tk_allow_stitch', 'false').lower() == 'true'
    ai_generated = request.POST.get('ai_generated', 'false').lower() == 'true'
    tk_to_everyone = request.POST.get('tk_to_everyone', 'false').lower() == 'true'
    tk_to_friends = request.POST.get('tk_to_friends', 'false').lower() == 'true'
    tk_to_only_me = request.POST.get('tk_to_only_me', 'false').lower() == 'true'
    tk_tiktok_mentions = request.POST.get('tk_tiktok_mentions',  None)

    tk_audience='PUBLIC_TO_EVERYONE'
    if tk_to_friends:
        tk_audience='MUTUAL_FOLLOW_FRIENDS'
    elif tk_to_only_me:
        tk_audience='SELF_ONLY'
    tk_description=f'{description} {hashTags} {tk_tiktok_mentions}'
        
    # Instagram
    to_ig_stories = request.POST.get('to_ig_stories', 'false').lower() == 'true'
    to_ig_posts = request.POST.get('to_ig_posts', 'false').lower() == 'true'
    to_ig_reels = request.POST.get('to_ig_reels', 'false').lower() == 'true'
    ig_copyright = request.POST.get('ig_copyright', 'false').lower() == 'true'
    ig_location_tags = request.POST.get('ig_location_tags', 'false').lower() == 'true'
    ig_product_tags = request.POST.get('ig_product_tags', 'false').lower() == 'true'

    # Facebook
    to_fb_stories = request.POST.get('to_fb_stories', 'false').lower() == 'true'
    to_fb_posts = request.POST.get('to_fb_posts', 'false').lower() == 'true'
    to_fb_reels = request.POST.get('to_fb_reels', 'false').lower() == 'true'
    fb_copyright = request.POST.get('fb_copyright', 'false').lower() == 'true'
    fb_location_tags = request.POST.get('fb_location_tags', None)
    
    fb_descr=f'{description} {hashTags} '
    # Reddit
    red_is_nsfw = request.POST.get('red_is_nsfw', 'false').lower() == 'true'
    red_is_spoiler = request.POST.get('red_is_spoiler', 'false').lower() == 'true'
    target_subs = request.POST.get('red_sub_selected', None)
    
    date_scheduled = request.POST.get('date_scheduled', None)

    if not all([company_id,description]):
        return Response({'error': 'Bad request'})
    
    tsbs=target_subs.split(',')
    cp = Company.objects.filter(company_id=company_id).first()

    files = request.FILES  # Access uploaded files
    gallery_items = []
    for field_name, file in files.items():
        temp_file_path = default_storage.save(file.name, file)
        absolute_file_path = default_storage.path(temp_file_path)
        gallery_items.append({"image_path": absolute_file_path,'content_type':file.content_type,"file_size": file.size })
    datetime_object= timezone.now()
    
    if isScheduled:
        time_format = "%A, %d %B %Y %I:%M %p"
        # Convert to datetime object
        datetime_object = datetime.strptime(date_scheduled, time_format)

    platform = []
    if not cp:
        return Response({'error': 'Bad request'})
    if tiktokSelected:
        platform.append('tiktok')
    if instagramSelected:
        platform.append('instagram')
    if facebookSelected:
        platform.append('facebook')
    if redditSelected:
        platform.append('reddit')
        
    post_id = uuid.uuid4()
    cpst = CompanyPosts(
        company=cp,
        post_id=post_id,
        platforms=platform,
        tags=hashTags,
        title=title,
        description=description,
        is_scheduled=isScheduled,
        has_media=hasMedia,
        date_scheduled= datetime_object
    )
    cpst.save()
  
    if not isScheduled:
        # post to the respective platforms
        if redditSelected:
            crp=CompanyReddit.objects.filter(company=cp).first()
            redThread=threading.Thread(target=postReddit,daemon=True,kwargs={
                'title':title,
                'description':description,
                'subs':tsbs,
                'hasMedia':hasMedia,
                'files':gallery_items,
                'nsfw_tag':red_is_nsfw,
                'spoiler_tag':red_is_spoiler,
                'red_refresh_token':crp.refresh_token,
                'post_id':post_id,
                'company':cp
                
                })
            redThread.start()
        if tiktokSelected:
            glctyp= gallery_items[0]['content_type']
            if not glctyp.startswith("video/"):
                return 'Non video'
            tkThread=threading.Thread(target=postTiktok,daemon=True,kwargs={
                'company':cp,
                'description':tk_description,
                'video':gallery_items[0],
                'duet':tk_allow_duet,
                'comment':tk_allow_comment,
                'stitch':tk_allow_stitch,
                'audience':tk_audience, 
                'post_id':post_id,          
                'mentions':tk_tiktok_mentions          
            })
            tkThread.start()
        if facebookSelected:
            cfb=CompanyFacebook.objects.filter(company=cp).first()
            if not cfb:
                return
            isVideo= False
            if hasMedia:
                glctyp= gallery_items[0]['content_type']
                if glctyp.startswith("video/"):
                    isVideo=True
            fbThread=threading.Thread(target=postFacebook,daemon=True,kwargs={
               'media':gallery_items,
               'page_id':cfb.page_id,
               'post_id':post_id,
               'access_token':cfb.page_access_token,
               'is_video':isVideo,
               'description':description,
               'has_media':hasMedia,
               'title':title,
               'to_stories':to_fb_stories,
               'to_post':to_fb_posts
                
            })
            fbThread.start()
        if instagramSelected:
            cig=CompanyInstagram.objects.filter(company=cp).first()
            igThread=threading.Thread(target=postInstagram,daemon=True,kwargs={
                'account_id':cig.account_id,
                'media':gallery_items,
                'access_token':cig.long_lived_token,
                'description':description,
                'has_media':hasMedia,
                'post_id':post_id,
                'to_stories':to_ig_stories,
                'to_post':to_ig_posts,
                'to_reels':to_ig_reels                
            })
            igThread.start()
    else:
        # scheduled
        pass
        # if hasMedia:
        #     for key,file in files.items():
        #         up=UploadedMedia(
        #             post=cpst,
        #             media=file
        #         )
        #         up.save()

        #     pass
    # if instagramSelected:
    #     cigp = CompanyInstagramPosts(
    #         post_id=post_id,
    #         to_stories=to_ig_stories,
    #         to_reels=to_ig_reels,
    #         to_posts=to_ig_posts,
    #         run_copyright=ig_copyright,
    #         has_copyright=False,
    #         is_published=False,
    #         location_tags=ig_location_tags,
    #         product_tags=ig_product_tags
    #     )
    #     cigp.save()
    # if redditSelected:
        # cred = CompanyRedditPosts(
        #     post_id=post_id,
        #     nsfw_tag=red_is_nsfw,
        #     spoiler_flag=red_is_spoiler,
        #     brand_flag=red_is_brand,
        #     target_subs=target_subs
        # )
        # cred.save()

    return Response({'success': 'success request'})


def logoutUser(request):
    logout(request)
    return redirect('landing')


def companyProfile(request, company_name):
    if not company_name:
        return render(request, '404error.html')
    cn = Company.objects.filter(company_link_name=company_name).first()
    if not cn:
        return render(request, '404error.html')


@api_view(['POST'])
def updateBusinessProfile(request):
    company_id = request.POST.get('company_id', None)
    email = request.POST.get('email', None)
    phone = request.POST.get('phone', None)
    about = request.POST.get('about', None)
    website = request.POST.get('website', None)
    whatsapp = request.POST.get('whatsapp', None)
    instagram = request.POST.get('instagram', None)
    tiktok = request.POST.get('tiktok', None)
    youtube = request.POST.get('youtube', None)
    twitter = request.POST.get('twitter', None)
    linkedin = request.POST.get('linkedin', None)
    facebook = request.POST.get('facebook', None)
    # Get image file from FILES
    image = request.FILES.get('image', None)
    cm = Company.objects.filter(company_id=company_id).first()
    if not cm:
        return Response({'updated': False})
    if image:
        cpp = CompanyProfilePicture.objects.filter(company=cm).first()
        if cpp:
            cpp.p_pic = image
        else:
            cpp = CompanyProfilePicture(
                company=cm,
                p_pic=image
            )
        cpp.save()
    cc = CompanyContacts.objects.filter(company=cm).first()
    if cc:
        cc.instagram = instagram
        cc.whatsapp = whatsapp
        cc.tiktok = tiktok
        cc.youtube = youtube
        cc.twitter = twitter
        cc.linkedin = linkedin
        cc.email = email
        cc.facebook = facebook
        cc.save()
    else:
        cc = CompanyContacts(
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
    cm.company_phone = phone if phone else cm.company_phone
    cm.company_website = website if website else cm.company_website
    cm.company_about = clean_html(about) if about else cm.company_about
    cm.save()

    return Response({'updated': True})


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
                return render(request, 'error.html',
                              {'error': publish_data.get('error', {}).get('message', 'Failed to publish media.')})

        return render(request, 'error.html',
                      {'error': media_data.get('error', {}).get('message', 'Failed to create media object.')})

    return render(request, 'upload_content.html')


def get_instagram_auth_url(company_id):
    """
    Generates the Instagram OAuth URL with a state parameter for session integrity.

    :param company_id: Unique identifier for the Company, such as a database Company ID.
    :return: OAuth URL with state parameter for user identification.
    """
    # Encode the user_id or other identifying data in the state parameter
    state = urllib.parse.quote_plus(str(company_id))  # Ensure URL encoding for special characters
    # pages_show_list,pages_manage_posts,pages_read_engagement,pages_manage_engagement,

    oauth_url = (
        f"https://www.facebook.com/v21.0/dialog/oauth"
        f"?client_id={settings.INSTAGRAM_CLIENT_ID}"
        f"&redirect_uri={settings.INSTAGRAM_REDIRECT_URI}"
        f"&scope=read_insights,business_management,instagram_basic,instagram_manage_comments,instagram_manage_insights,instagram_content_publish,instagram_manage_messages,pages_read_engagement,pages_manage_engagement"
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
        f"&scope=pages_show_list,pages_manage_posts,pages_read_engagement,pages_manage_engagement,business_management,pages_manage_metadata,pages_messaging,pages_read_user_content,read_insights"
        f"&state={state}"
    )
    return oauth_url


@api_view(['GET'])
def instagram_callback(request):
    code = request.GET.get('code')
    state = request.GET.get("state")  # Retrieve the state parameter
    company_id = urllib.parse.unquote_plus(state)  # Decode the state to get the original user_id
    token_url = f"https://graph.facebook.com/v21.0/oauth/access_token?client_id={settings.FACEBOOK_APP_ID}&redirect_uri={settings.INSTAGRAM_REDIRECT_URI}&client_secret={settings.FACEBOOK_APP_SECRET}&code={code}"
    response = requests.get(token_url)
    data = response.json()
    access_token = data.get('access_token')
    cm = Company.objects.filter(company_id=company_id).first()
    if not cm:
        return redirect('dashboard', company_id=company_id)
    
    
    pg_id = get_facebook_ig_page_id(access_token)
    ci = CompanyInstagram.objects.filter(company=cm).first()
    inst_id = get_instagram_account_id(access_token, pg_id)
    insgts = get_instagram_account_insights(access_token, inst_id)
    l_lived_token = get_long_lived_token(access_token)
    if ci:
        ci.short_lived_token = access_token
        ci.account_id = inst_id
        ci.long_lived_token = l_lived_token
        ci.linked = True
        ci.active = True
        ci.account_name = insgts['username']
        ci.profile_url = insgts['profile_picture_url']
        ci.followers_trend.append(insgts['followers_count'])
        ci.impressions.append(insgts['impressions'])
        ci.reach.append(insgts['reach'])
        ci.save()

    else:
        ci = CompanyInstagram(
            company=cm,
            short_lived_token=access_token,
            account_id=inst_id,
            long_lived_token=l_lived_token,
            linked=True,
            active=True,
            account_name=insgts['username'],
            profile_url=insgts['profile_picture_url']
        )
        ci.followers_trend.append(insgts['followers_count'])
        ci.impressions.append(insgts['impressions'])
        ci.reach.append(insgts['reach'])
        ci.save()

    return redirect('dashboard', company_id=company_id)


def get_facebook_ig_page_id(page_access_token):
    # page_access_token='EAAXHx5IkuqcBOxJORLpQ4QZCdRoZCfiAIohsqeyoJStcjTncSkfqnMPxpVPDAc0N2JWv9kXEbZBU2pNkBZB55PEqmhCvLSM8W2l9ndtiYZBnZBYytMyhOLKM1cC18o4un8YqFnE1LG5iZB8EgLqvJg4ZAF5RuMR8AYM3Ge2P3ypZClHyU3usO459tGye73PfzuDrdYX6jC6fTfx2IQdaoYQZDZD'
    page_url = f"https://graph.facebook.com/v21.0/me/accounts"
    params = {"access_token": page_access_token}
    response = requests.get(page_url, params=params)
    page_data = response.json()
    page_id = page_data['data'][0]['id']
    return page_id


def get_instagram_account_id(page_access_token, page_id):
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


def get_instagram_account_insights(access_token, instagram_account_id,**kwargs):
    """
    Retrieves basic data, profile information, and analytics for an Instagram Business account.

    :param access_token: The long-lived Instagram access token.
    :param instagram_account_id: The ID of the Instagram Business account.
    :return: A dictionary containing basic account metrics, username, and profile picture.
    """
    url = f"https://graph.facebook.com/v21.0/{instagram_account_id}"
    params = {
        "fields": "follows_count,followers_count,media_count,username,profile_picture_url",
        "access_token": access_token
    }

    response = requests.get(url, params=params)
    data = response.json()
    # Check for errors in the response
    if "error" in data:
        raise Exception(f"Error fetching insights: {data['error']['message']}")

    # Additional insights (optional)
    insights_url = f"https://graph.facebook.com/v21.0/{instagram_account_id}/insights"
    insights_params = {
        "metric": "impressions,reach",
        "period": "day",
        "access_token": access_token
    }

    insights_response = requests.get(insights_url, params=insights_params)
    insights_data = insights_response.json()
    

    if "error" in insights_data:
        raise Exception(f"Error fetching insights data: {insights_data['error']['message']}")

    # Combine account data and insights for easier access
    cp_id=kwargs.get('company_id',None)
    if cp_id:
        cp=Company.objects.filter(company_id=cp_id).first()
        if cp:
            cig=CompanyInstagram.objects.filter(company=cp).first()
            if cig:
                tnw=timezone.now()
                tdiff=tnw-cig.last_update_time
                if tdiff.total_seconds()>86400:
                    # cig.followers_trend=[]
                    # cig.impressions=[]
                    # cig.reach=[]
                    cig.last_update_time=timezone.now()
                    cig.followers_trend.append(data.get("followers_count"))
                    cig.impressions.append(insights_data["data"][0]["values"][-1]['value'])
                    cig.reach.append(insights_data["data"][1]["values"][-1]['value'])
                    # saving fpl 
                    cig.save()

    account_data = {
        "followers_count": data.get("followers_count"),
        "media_count": data.get("media_count"),
        "account_type": data.get("account_type"),
        "username": data.get("username"),
        "profile_picture_url": data.get("profile_picture_url"),
        "impressions": insights_data["data"][0]["values"] if "data" in insights_data else None,
        "reach": insights_data["data"][1]["values"] if "data" in insights_data else None,
    }

    return account_data


def get_facebook_page_insights(access_token, page_id, **kwargs):
    url = f"https://graph.facebook.com/v21.0/{page_id}"
    params = {
        "fields": "name,username,picture,fan_count",
        "access_token": access_token
    }

    response = requests.get(url, params=params)
    profile_info = response.json()

    url2 = f"https://graph.facebook.com/v21.0/{page_id}/insights"
    params2 = {
        "metric": "page_impressions,page_fans,page_views_total",
        "access_token": access_token,
        'period':'day'
    }

    response = requests.get(url2, params=params2)
    page_insights = response.json()
    page_impress=0
    page_fans=0
    page_vws=0
    for pg in page_insights.get('data'):
        pim=pg.get('name')
        if pim == 'page_impressions':
            prd=pg.get('period')
            vll=pg.get('values')[-1].get('value')
            page_impress=vll
            
        if pim == 'page_views_total':
            vll=pg.get('values')[-1].get('value')
            page_vws=vll
            
        if pim == 'page_fans':
            vll=pg.get('values')[-1].get('value')
            page_fans=vll
    
    # print(page_insights.get('data').get('page_fans'))
    vl_id=kwargs.get('company_id',None)
    if vl_id:
        cp=Company.objects.filter(company_id=vl_id).first()
        if cp:
            cmf=CompanyFacebook.objects.filter(company=cp).first()
            
            if cmf:
                tnw=timezone.now()
                tdiff=tnw-cmf.last_update_time
                if tdiff.total_seconds()>86400:
                # cmf.page_fans=[]
                # cmf.page_views_total=[]
                # cmf.impressions=[]

                    cmf.page_fans.append(page_fans)
                    cmf.page_views_total.append(page_vws)
                    cmf.impressions.append(page_impress)
                    cmf.last_update_time=timezone.now()
                    # cmf.page_fans.append(i for i in page_fans)
                    # cmf.page_views_total.append(i for i in page_vws)
                    # cmf.impressions.append(i for i in page_impress)
                    cmf.save()
    return {
        'page_name': profile_info.get("name"),
        'page_username': profile_info.get("username"),
        'fan_count': profile_info.get("username"),
        'p_picture': profile_info.get("picture", {}).get("data", {}).get("url"),
        'page_impressions': page_impress,
        'page_fans': page_fans,
        'page_views_total': page_vws,
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
    access_token = data.get('access_token')
    cm = Company.objects.filter(company_id=company_id).first()
    if not cm:
        return redirect('dashboard', company_id=company_id)
    pg_id = get_facebook_ig_page_id(access_token)
    l_lived_token = get_long_lived_token(access_token)
    cf = CompanyFacebook.objects.filter(company=cm).first()
    insgts = get_facebook_page_insights(access_token, pg_id)
    
    pages_url = f"https://graph.facebook.com/v21.0/me/accounts"
    headers = {"Authorization": f"Bearer {access_token}"}
    pages_response = requests.get(pages_url, headers=headers)
    pages_data = pages_response.json()
    if 'data' not in pages_data:
        return 

    # Extract Page ID and Page Access Token for the first Page
    page = pages_data['data'][0]
    page_id = page.get('id')
    page_access_token = page.get('access_token')
    if cf:
        cf.short_lived_token = access_token
        cf.account_id = pg_id
        cf.long_lived_token = l_lived_token
        cf.linked = True
        cf.active = True
        cf.page_access_token=page_access_token
        cf.page_id = page_id
        cf.account_name = insgts['page_name']
        cf.profile_url = insgts['p_picture']
        cf.followers_trend.append(insgts['fan_count'])
        cf.impressions.append(insgts['page_impressions'])
        cf.profile_views.append(insgts['page_views_total'])
        cf.page_fans.append(insgts['page_fans'])
        cf.save()
    else:
        cf = CompanyFacebook(
            company=cm,
            short_lived_token=access_token,
            account_id=pg_id,
            long_lived_token=l_lived_token,
            page_access_token=page_access_token,
            linked=True,
            active=True,
            page_id=page_id,
            account_name=insgts['page_name'],
            profile_url=insgts['p_picture'],
        )
        cf.followers_trend.append(insgts['fan_count'])
        cf.impressions.append(insgts['page_impressions'])
        cf.page_negative_feedback.append(insgts['page_negative_feedback'])
        cf.profile_views.append(insgts['page_views_total'])
        cf.page_engaged_users.append(insgts['page_engaged_users'])
        cf.page_fans.append(insgts['page_fans'])
        cf.save()

    return redirect('dashboard', company_id=company_id)


def tiktok_auth_link(company_id):
    client_id = settings.TIKTOK_CLIENT_ID  # Replace with your TikTok app's client ID
    redirect_uri = settings.TIKTOK_REDIRECT_URI  # Replace with your redirect URI
    scope = "user.info.basic,user.info.profile,user.info.stats,video.list,video.publish,video.upload"  # Adjust scopes as needed
    state = urllib.parse.quote_plus(str(company_id))  # Ensure URL encoding for special characters

    auth_url = (
        f"https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope={scope}"
        f"&state={state}"
    )

    return auth_url


@csrf_exempt
def tiktok_callback(request):
    """Handles the TikTok callback and exchanges code for an access token."""

    code = request.GET.get('code')
    state = request.GET.get("state")  # Retrieve the state parameter
    company_id = urllib.parse.unquote_plus(state)  # Decode the state to get the original user_id

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
    refresh_token = response.json().get("refresh_token")

    if not access_token:
        return redirect('dashboard', company_id=company_id)
    cm = Company.objects.filter(company_id=company_id).first()
    if not cm:
        return redirect('dashboard', company_id=company_id)

    # Store access token in session or database for later use
    ctk = CompanyTiktok.objects.filter(company=cm).first()
    data = tiktok_profile_stat(access_token)
    if not ctk:
        ctk = CompanyTiktok(
            company=cm,
            active=True,
            linked=True,
            access_token=access_token,
            refresh_token=refresh_token,
            account_name=data['disp_name'],
            account_username=data['u_name'],
            profile_url=data['ppic'],
            account_id=data['user_id'],
        )
        ctk.followers_count.append(data['f_count'])
        ctk.likes_count.append(data['l_count'])
        ctk.save()
    else:
        ctk.company = cm
        ctk.active = True
        ctk.linked = True
        ctk.access_token = access_token
        ctk.refresh_token = refresh_token
        ctk.account_name = data['disp_name']
        ctk.account_username = data['u_name']
        ctk.profile_url = data['ppic']
        ctk.account_id = data['user_id']
        ctk.followers_count.append(data['f_count'])
        ctk.likes_count.append(data['l_count'])
        ctk.save()

    return redirect('dashboard', company_id=company_id)


def tiktok_profile_stat(access_token):
    url = 'https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name,username,follower_count,likes_count'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(url, headers=headers)
    dta = response.json().get('data', {}).get('user')
    return {
        'user_id': dta.get('union_id'),
        'ppic': dta.get('avatar_url'),
        'disp_name': dta.get('display_name'),
        'u_name': dta.get('username'),
        'f_count': dta.get('follower_count'),
        'l_count': dta.get('likes_count')
    }


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

def getRedditSubInfo(subs,reddit):
    print('getting subs analytics ',subs)
    for sub in subs:
        crs=CompanyRedditSubs.objects.filter(sub_name=sub).first()
        if crs:
            # check the last time it was updated
            lst_upd=crs.last_updated
            dfr=(timezone.now()-lst_upd).total_seconds()
            if dfr > 3600: # updated more than 1hr ago
                sr=reddit.subreddit(sub)
                crs.full_name=sr.name
                crs.description=sr.description
                crs.subscriber_count=sr.subscribers
                crs.user_is_banned=sr.user_is_banned
                pr=sr.rules() 
                rules=pr['rules']
                rls=[]
                for r in rules:
                    rls.append(
                        {'rule':r['short_name'],'description':r['description']}
                    )
                crs.sub_rules=rls
                crs.last_updated-timezone.now()
                crs.save()
        else:
            sr=reddit.subreddit(sub)
            pr=sr.rules() 
            rules=pr['rules']
            rls=[]
            for r in rules:
                rls.append(
                    {'rule':r['short_name'],'description':r['description']}
                )

            crs=CompanyRedditSubs(
                sub_name=sub,
                full_name=sr.name,
                description=sr.description,
                subscriber_count=sr.subscribers,
                user_is_banned=sr.user_is_banned,
                sub_rules=rls
            )
            crs.save()

@api_view(['POST'])
def subRedInfo(request):
    subs = request.POST.get('subs', None)
    company_id = request.POST.get('company_id', None)
    if not all([company_id, subs]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    subs = subs.split(',')
    subs = [r.split('r/')[-1] for r in subs]
    dt=[]
    for sub in subs:
        crs=CompanyRedditSubs.objects.filter(sub_name=sub).first()
        if crs:
            dt.append({
                    'name': crs.sub_name,
                    'description': crs.description,
                    'subscribers': crs.subscriber_count,
                    'isBanned': crs.user_is_banned,
                    'rules':crs.sub_rules
                    })
        else:
            sr=reddit.subreddit(sub)
            pr=sr.rules() 
            rules=pr['rules']
            rls=[]
            for r in rules:
                rls.append(
                    {'rule':r['short_name'],'description':r['description']}
                )

            crs=CompanyRedditSubs(
                sub_name=sub,
                full_name=sr.name,
                description=sr.description,
                subscriber_count=sr.subscribers,
                user_is_banned=sr.user_is_banned,
                sub_rules=rls
            )
            crs.save()
            dt.append({
                    'name': crs.sub_name,
                    'description': crs.description,
                    'subscribers': crs.subscriber_count,
                    'isBanned': crs.user_is_banned,
                    'rules':crs.sub_rules
                    })
    context = {
        'sub_info': dt,
    }
    return render(request, 'dashboard.html', context=context)
    
@api_view(['POST'])
def redditFlairs(request):
    subs = request.POST.get('subs', None)
    company_id = request.POST.get('company_id', None)

    if not all([company_id, subs]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    subs = subs.split(',')
    subs = [r.split('r/')[-1] for r in subs]
    cr = CompanyReddit.objects.filter(company=cp).first()
    
    
    rt = []
    if cr:
        reddit = praw.Reddit(
            client_id=settings.REDDIT_CLIENT_ID,
            client_secret=settings.REDDIT_CLIENT_SECRET,
            user_agent=settings.REDDIT_USER_AGENT,
            refresh_token=cr.refresh_token,
        )
        # get sub trasssic analysis
        sub_analyt_thrd=threading.Thread(target=getRedditSubInfo,daemon=True,kwargs={'subs':subs,'reddit':reddit})
        sub_analyt_thrd.start()

        # check if we have the flairs already
        for subreddit_name in subs:
            present = False
            for sr in cr.subs:
                if sr['sub'] == subreddit_name:
                    present = True
                    rt.append({'sub_r': subreddit_name,
                               'flairs_r': sr['flairs']})
            if not present:
                try:
                    subreddit = reddit.subreddit(subreddit_name)
                    flair_options = list(subreddit.flair.link_templates)
                    vl = []
                    for f in flair_options:
                        if not f['mod_only']:
                            vl.append({
                                'name': f['text'],
                                'id': f['id'],
                                'selected': False
                            })
                    rt.append({
                        'sub_r': subreddit_name,
                        'flairs_r': vl})
                except:
                    continue

    context = {
        'flair_results': rt,
    }
    return render(request, 'dashboard.html', context=context)


@api_view(['POST'])
def updateFlairs(request):
    flairs = request.POST.get('flairs', None)
    company_id = request.POST.get('company_id', None)
    if not all([company_id, flairs]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    cr = CompanyReddit.objects.filter(company=cp).first()
    modified = False
    init_sub=[]
    if cr:
        init_sub = cr.subs
        for flr in json.loads(flairs):
            for sr in init_sub:
                if flr['name'] == sr['sub']:
                    for f_id in sr['flairs']:
                        if f_id['id'] == flr['id']:
                            f_id['selected'] = True
                            pass
                        else:
                            f_id['selected'] = False
                        modified = True  # Mark as modified
    if modified:
        cr.subs=init_sub
        cr.save()
    return Response({'success': 'Updated successfully'})


def reddit_auth_link(company_id):
    state = urllib.parse.quote_plus(str(company_id))  # Ensure URL encoding for special characters
    authorization_url = reddit.auth.url(['identity', 'submit', 'read', 'mysubreddits', 'flair',"history",'modposts'], state=state,
                                        duration='permanent', )
    return authorization_url


def reddit_callback(request):
    code = request.GET.get('code')
    state = request.GET.get('state')
    company_id = urllib.parse.unquote_plus(state)  # Decode the state to get the original user_id

    if code:
        refresh_token = reddit.auth.authorize(code)
        # access_token = reddit.auth.access_token
        cm = Company.objects.filter(company_id=company_id).first()
        if not cm:
            return redirect('dashboard', company_id=company_id)

        cr = CompanyReddit.objects.filter(company=cm).first()
        red_user = reddit.user.me()  # Get the authenticated user
        if not cr:
            cr = CompanyReddit(
                company=cm,
                active=True,
                linked=True,
                # access_token=access_token,
                refresh_token=refresh_token,  # update the access token every 1 day
                account_username=red_user.name,
                profile_url=red_user.icon_img,
                comment_karma=red_user.comment_karma,
                link_karma=red_user.link_karma
            )
            cr.save()
        else:
            cr.delete()
            cr = CompanyReddit(
                company=cm,
                active=True,
                linked=True,
                # access_token=access_token,
                refresh_token=refresh_token,  # update the access token every 1 day
                account_username=red_user.name,
                profile_url=red_user.icon_img,
                comment_karma=red_user.comment_karma,
                link_karma=red_user.link_karma
            )
            cr.save()

    return redirect('dashboard', company_id=company_id)


def pinterest_auth_link(company_id):
    pass


def pinterest_callback(request):
    pass
