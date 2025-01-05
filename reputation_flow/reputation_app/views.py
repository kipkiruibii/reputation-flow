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
import ffmpeg
import os
import pdfplumber
import pytz
import mimetypes
from django.contrib.gis.geoip2 import GeoIP2
from user_agents import parse
import boto3
import tempfile
from paypal.standard.forms import PayPalPaymentsForm
           
s3_client = boto3.client(
    's3',
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_S3_REGION_NAME,
)


def get_client_ip(request):
    """Extract client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    return ip,user_agent

def get_user_location(request,page):
    """Get user's location using GeoIP2."""
    ip,user_agent = get_client_ip(request)
    user_agent_obj = parse(user_agent)
    geo = GeoIP2()
    try:
        location = geo.city(ip)
        stats=SiteAnalytics(
            page_visited=page,
            request_header=user_agent,   
            country=location['country_name'],  
            ip_address=ip,  
            city=location['city'], 
            browser=user_agent_obj.browser.family,  
            os=user_agent_obj.os.family,   
            location={'latitiude':location['latitude'], 'longitude': location['longitude']}, # {latitude:1222,longitude:133}  
            is_mobile=user_agent_obj.is_mobile, 
            is_tablet=user_agent_obj.is_tablet, 
            is_pc=user_agent_obj.is_pc 
        )
        stats.save()
    except Exception as e:
        stats=SiteAnalytics(
            page_visited=page,
            request_header=user_agent,   
            error= str(e), 
            is_error=True  
        )
        stats.save()

def delete_file_from_s3(file_key):
    try:
        # Delete the file from S3
        s3_client.delete_object(
            Bucket=settings.AWS_STORAGE_BUCKET_NAME,
            Key=file_key,
        )
                
        return JsonResponse({"message": "File deleted successfully."})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
    # import magic 

def delete_temp_files(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)  # Deletes the file
            print(f"Deleted temp file: {file_path}")
        else:
            print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error deleting file {file_path}: {str(e)}")
            

ALLOWED_MIME_TYPES = [
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "video/mp4", "video/quicktime", "video/x-msvideo", "video/x-matroska", "video/webm",
    "application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "text/plain"
]


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


@csrf_exempt
def successful_payment(request):
    print('payment successful')
    if request.method == "POST":
        data = request.POST
        print(data)

    # save the client payment database
    return render(request, 'payment_successful.html')


@csrf_exempt
def failed_payment(request):
    print('payment failed')
    return render(request, 'payment_failed.html')


@csrf_exempt
def paypal_notification(request):
    print('Received notification')
    if request.method == "POST":
        data = request.POST
        print('Received paypal',data)
        try:
            payment_status = data.get('payment_status', '')
            currency = data.get('mc_currency', '')
            amount = data.get('mc_gross', '')
            email = data.get('payer_email', '')
            transaction_id = data.get('txn_id', '')
            transaction_subject = data.get('transaction_subject', '')
            payment_date = data.get('payment_date', '')
            receiver_email = data.get('receiver_email', '')
            profile_id = data.get('subscr_id', '')
            company_id = request.POST.get('custom', '')
            cpn = Company.objects.filter(company_id=company_id).first()
            if cpn:
                if payment_status == 'Completed':
                    if company_id:
                        if currency == 'USD':
                            if float(amount) >= 29:
                                cth=CompanyTransactionHistory(
                                    company=cpn,
                                    subscription_type='Starter',# eg starter company or enterprise
                                    subscription_tier=1, # 1- starter 2-company 3-enterprise
                                    subscription_amount=29,
                                    subscription_currency='USD',
                                    subscription_success=True,
                                    transaction_id=transaction_id,
                                    payer_email=email,
                                    subscriber_id=profile_id,
                                    subscription_notes=f'Subscription successful on {payment_date}',
                                    subscription_period={'start_date':timezone.now().isoformat(),'end_date':(timezone.now()+timedelta(days=30)).isoformat()}
                                )
                                cth.save()
                                
                                # update the company profile
                                
                                cpn.company_free_trial=False
                                cpn.company_subscription_date=timezone.now()
                                cpn.company_active_subscription=True
                                cpn.company_subscription_tier=1
                                cpn.company_subscription='Starter'
                                cpn.save()
                                
                    return JsonResponse({'result':200})
                            # elif float(amount) >= 9.99:
                            #     request_remaining = 2000
                            #     subscription_type = 'Personal Monthly'
                            # if request_remaining:
                            #     u = UserDetails.objects.filter(user=user_paying).first()
                            #     u.subscription_active = True
                            #     u.request_remaining += request_remaining
                            #     u.subscription_expiry = timezone.now() + timedelta(days=30)
                            #     u.subscription_type = subscription_type
                            #     u.save()
                            # us = UserTransactions(
                            #     user=user_paying,
                            #     subscriber_id=profile_id,
                            #     receiver_email=email,
                            #     payment_date=payment_date,
                            #     transactionId=transaction_id,
                            #     subscription_type=subscription_type,
                            #     amount=amount,
                            #     is_successful=True
                            # )
                            # us.save()
                elif payment_status == '':
                    pass
                else:
                    cth=CompanyTransactionHistory(
                        company=cpn,
                        subscription_type='starter',# eg starter company or enterprise
                        subscription_tier=-1, # 1- starter 2-company 3-enterprise
                        subscription_amount=float(amount) if amount else 0.0,
                        subscription_currency=currency,
                        subscription_failed=True,
                        transaction_id=transaction_id,
                        payer_email=email,
                        subscriber_id=profile_id,
                        subscription_notes=f'Subscription of {currency} {amount} Failed : {payment_status}',
                        subscription_period={'start_date':timezone.now().isoformat(),'end_date':(timezone.now()+timedelta(days=30)).isoformat()}
                    )
                    cth.save()
        except:
            traceback.print_exc()
        return JsonResponse({'result':500})


# Create your views here.
def index(request):
    """
    Landing page
    """
    trd=threading.Thread(target=get_user_location,daemon=True, kwargs={'request':request,'page':'landing'})
    trd.start()

    if request.user.is_authenticated:
        # grab the member and their company
        mp = MemberProfile.objects.filter(user=request.user).first()
        if mp:
            cm = CompanyMember.objects.filter(member=mp).first()
            if cm:
                user_comp = cm.company.company_id
                
                host = request.get_host()
                starter_paypal_checkout = {
                    'business': settings.PAYPAL_RECEIVER_EMAIL,
                    'a3': '29',  # Recurring price
                    'p3': '1',  # Payment interval (every 1 month)
                    't3': 'M',  # Time unit (M for months)
                    'item_name': 'Monthly Subscription Plan(Starter)',
                    'src': '1',  # Recurring payments enabled
                    'sra': '1',  # Reattempt on payment failure
                    "custom": user_comp,
                    'currency_code': 'USD',
                    'invoice': str(uuid.uuid4()),  # unique identifier for each transaction
                    'notify_url': request.build_absolute_uri(reverse('paypal_notification')),
                    'return_url': f"http://{host}{reverse('payment-success')}",
                    'cancel_return': f"http://{host}{reverse('payment-failed')}",
                    'cmd': '_xclick-subscriptions',  # Specify that this is a subscription button
                }
                starter_plan = PayPalPaymentsForm(initial=starter_paypal_checkout, button_type='subscribe')
                context = {
                    'starter_plan': starter_plan,
                    'current_plan':cm.company.company_subscription_tier if cm.company.company_active_subscription else -1,
                }
    
                return render(request, 'index.html',context=context)
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
                return Response({'result': False, 'message': 'Company profile already exists'},
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
            bsn=businessName.strip().replace(' ','-')
            current_url = request.build_absolute_uri()
            fin_link=current_url+bsn
            c = Company(
                company_name=businessName,
                company_category=businessCategory,
                company_id=uuid.uuid4(),
                company_phone=telephone,
                company_address=address1,
                company_address2=address2,
                company_review_link=fin_link,
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
            trd=threading.Thread(target=get_user_location,daemon=True, kwargs={'request':request,'page':'signup'})
            trd.start()

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

    if cr:
        reddit_subs = [s['sub'] for s in cr.subs]
        lu = cr.last_updated
        tn = (timezone.now() - lu).total_seconds()
        try:
            # check if there is a new sub,
            # if no new sub wait 1hour before updating the flairs 
            # if new sub update the flairs of the new sub
            reddit = praw.Reddit(
                client_id=settings.REDDIT_CLIENT_ID,
                client_secret=settings.REDDIT_CLIENT_SECRET,
                user_agent=settings.REDDIT_USER_AGENT,
                refresh_token=cr.refresh_token,
            )
            for subreddit_name in reddit.user.subreddits(limit=None):
                if tn < 3600 and subreddit_name.display_name in reddit_subs:
                    continue
                flair_options = []
                vl = []
                try:
                    subreddit = reddit.subreddit(subreddit_name.display_name)
                    flair_options = list(subreddit.flair.link_templates)
                    flair_optional = not subreddit.post_requirements().get('flair', False)
                    for f in flair_options:
                        if not f['mod_only']:
                            vl.append({
                                'name': f['text'],
                                'id': f['id'],
                                'selected': False,

                            })

                except Exception as e:
                    flair_optional = True

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
                            if vl:
                                sb['flairs'].append(vl)
                cr.last_updated = timezone.now()
                cr.save()
                if not present:
                    cr.subs.append(
                        {
                            'sub': subreddit_name.display_name,
                            'flair_optional': flair_optional,
                            'flairs': vl
                        }
                    )
                    print('saved llx', subreddit_name.display_name)
                    cr.save()
        except:
            pass


def format_datetime(timezone_str, datetime_str, platform):
    # Sample data from AJAX

    # Parse the datetime string
    # if platform.strip() == 'facebook':
    # utc_datetime = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S%z")
    utc_datetime = datetime_str
    # if platform.strip() == 'reddit':
    #     utc_datetime = datetime.fromtimestamp(datetime_str,tz=timezone.utc)
    # Convert to the specified timezone

    target_tz = pytz.timezone(timezone_str)
    local_datetime = utc_datetime.astimezone(target_tz)

    # Get the current time in the same timezone
    now = datetime.now(target_tz)

    # Format output based on date relation
    if local_datetime.date() == now.date():
        # Same day: "Today hh:mm AM/PM"
        formatted = local_datetime.strftime("Today %I:%M %p")
    elif local_datetime.date() == (now - timedelta(days=1)).date():
        # One day before: "Yesterday hh:mm AM/PM"
        formatted = local_datetime.strftime("Yesterday %I:%M %p")
    else:
        # Other dates: "day/date/month/year hh:mm AM/PM"
        formatted = local_datetime.strftime("%a/%d/%m/%Y %I:%M %p")

    return formatted

@api_view(['POST'])
def settingProfile(request):
    company_id = request.POST.get('company_id', None)
    type_ = request.POST.get('set_p', None)
    if not all([type_,company_id]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    if type_=='show_page':
        cp.company_show_page=not cp.company_show_page
        cp.save()
    if type_=='enable_ai':
        cp.company_enable_ai=not cp.company_enable_ai
        cp.save()
    return Response({'success': 'Updated successfully'})

@api_view(['POST', 'GET'])
def postDispute(request):
    company_id = request.POST.get('company_id', None)
    timezone_ = request.POST.get('timezone', None)
    title = request.POST.get('title', None)
    message = request.POST.get('message', None)
    if not all([company_id, title,message]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})

    ctd=CompanyTransactionDisputes(
            company=cp,
            title=title,
            description=message,
            timezone_str=timezone_
        )
    ctd.save()
    dispts=[]
    for disp in CompanyTransactionDisputes.objects.filter(company=cp).order_by('-pk'):
        dispts.append({
            'title':disp.title,
            'description':disp.description,
            'date_sent':format_datetime(datetime_str=disp.date_sent, timezone_str=timezone_,
                                                 platform='-'),
        })
    context={
        'disputes':dispts
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)

    
@api_view(['POST', 'GET'])
def replyPM(request):
    company_id = request.POST.get('company_id', None)
    platform = request.POST.get('platform', None)
    timezone_s = request.POST.get('timezone', 'UTC')
    conv_id = request.POST.get('conversation_id', None)
    recipient_id = request.POST.get('recipient_id', None)
    message = request.POST.get('message', None)
    if not all([company_id, platform, conv_id, message]):
        return Response({'error': 'Bad request'})
    convs = []

    if platform.strip() == 'instagram':
        pass
    if platform.strip() == 'facebook':
        cp = Company.objects.filter(company_id=company_id).first()
        if not cp:
            return Response({'error': 'Bad request'})
        
        # check subscription
        if not any([cp.company_free_trial, cp.company_active_subscription]):
            return Response({'error': 'Kindly renew your subscription to continue.'})
        
        
        cfb = CompanyFacebook.objects.filter(company=cp).first()
        if not cfb:
            return Response({'error': 'Bad request'})
        cig = CompanyInstagram.objects.filter(company=cp).first()
        if not cig:
            return Response({'error': 'Bad request'})
        url = f"https://graph.facebook.com/v21.0/{cfb.page_id}/messages"
        params = {
            "access_token": cfb.page_access_token,

        }
        data = {
            "message": {'text': message},
            "recipient": {"id": recipient_id},
            "messaging_type": "RESPONSE",
        }
        # response = requests.get(url, params=params)
        response = requests.post(url, params=params, json=data)
        if response.json().get('recipient_id', None):
            # grab items to refresh page
            url = f"https://graph.facebook.com/v21.0/{conv_id}/messages"
            params = {"access_token": cfb.page_access_token, "fields": "message,from,created_time"}
            response = requests.get(url, params=params)
            data = response.json()['data']
            cnvm = ConversationMessages.objects.filter(conversation_id=conv_id)
            if cnvm:
                for c in data:
                    cnvk = cnvm.filter(message_id=c['id']).first()
                    f_id = c['from']['id']
                    if not cnvk:
                        cnvk = ConversationMessages(
                            conversation_id=conv_id,
                            message_id=c['id'],
                            sender=c['from']['name'],
                            sender_id=c['from']['id'],
                            message=c['message'],
                            is_me=f_id == cfb.account_id,
                            created_at=datetime.strptime(c['created_time'], "%Y-%m-%dT%H:%M:%S%z")
                        )
                        cnvk.save()
                    else:
                        cnvk.message = c['message']
                        cnvk.save()
            else:
                for c in data:
                    f_id = c['from']['id']
                    cnvk = ConversationMessages(
                        conversation_id=conv_id,
                        message_id=c['id'],
                        sender=c['from']['name'],
                        sender_id=c['from']['id'],
                        message=c['message'],
                        is_me=f_id == cfb.account_id,
                        created_at=datetime.strptime(c['created_time'], "%Y-%m-%dT%H:%M:%S%z")
                    )
                    cnvk.save()
            cms = ConversationMessages.objects.filter(conversation_id=conv_id).order_by('created_at')
            for conv in cms:
                convs.append({
                    'message': conv.message,
                    'date_sent': format_datetime(datetime_str=conv.created_at, timezone_str=timezone_s,
                                                 platform='facebook'),
                    'from': conv.sender,
                    'me': conv.is_me,
                })
            # convs.reverse()
            context = {
                'pm_messages': convs,
                'conversation_id': conv_id,
                'pm_platform': platform,
                'pm_recipient_id': recipient_id,
                'pm_reply_supported': True
            }
            if request.user_agent.is_pc:
                return render(request, 'dashboard.html', context=context)
            else:
                return render(request, 'dashboard_mobile.html', context=context)
        else:
            print(response.json())
            if response.json()['error']['code']==10:
                message='This message is being sent outside the allowed window (24 hours).Kindly use official site/app to reply.'
                return Response({'error': message})

            return Response({'error': 'Could not send message. Try again after sometime or use official site/app'})

    return Response({'success': 'Bad request'})


@api_view(['POST', 'GET'])
def getMessages(request):
    company_id = request.POST.get('company_id', None)
    platform = request.POST.get('platform', None)
    timezone_s = request.POST.get('timezone', 'UTC')
    conv_id = request.POST.get('conv_id', None)
    sender_id = request.POST.get('sender_id', None)

    if not all([company_id, platform, conv_id]):
        return Response({'error': 'Bad request'})
    convs = []
    if platform.strip() == 'facebook':
        cp = Company.objects.filter(company_id=company_id).first()
        if not cp:
            return Response({'error': 'Bad request'})
        cfb = CompanyFacebook.objects.filter(company=cp).first()
        if not cfb:
            return Response({'error': 'Bad request'})

        def getmsgs():
            url = f"https://graph.facebook.com/v21.0/{conv_id}/messages"
            params = {"access_token": cfb.page_access_token, "fields": "message,from,created_time"}
            response = requests.get(url, params=params)
            data = response.json()['data']
            cnvm = ConversationMessages.objects.filter(conversation_id=conv_id)
            if cnvm:
                for c in data:
                    cnvk = cnvm.filter(message_id=c['id']).first()
                    f_id = c['from']['id']
                    if not cnvk:
                        cnvk = ConversationMessages(
                            conversation_id=conv_id,
                            message_id=c['id'],
                            sender=c['from']['name'],
                            sender_id=c['from']['id'],
                            message=c['message'],
                            is_me=f_id == cfb.account_id,
                            created_at=datetime.strptime(c['created_time'], "%Y-%m-%dT%H:%M:%S%z")
                        )
                        cnvk.save()
                    else:
                        cnvk.message = c['message']
                        cnvk.save()
            else:
                for c in data:
                    f_id = c['from']['id']
                    cnvk = ConversationMessages(
                        conversation_id=conv_id,
                        message_id=c['id'],
                        sender=c['from']['name'],
                        sender_id=c['from']['id'],
                        message=c['message'],
                        is_me=f_id == cfb.account_id,
                        created_at=datetime.strptime(c['created_time'], "%Y-%m-%dT%H:%M:%S%z")
                    )
                    cnvk.save()

        cms = ConversationMessages.objects.filter(conversation_id=conv_id)
        if cms:
            trgt = threading.Thread(target=getmsgs, daemon=True)
            trgt.start()
        else:
            getmsgs()
        cms = ConversationMessages.objects.filter(conversation_id=conv_id).order_by('created_at')
        for conv in cms:
            convs.append({
                'message': conv.message,
                'date_sent': format_datetime(datetime_str=conv.created_at, timezone_str=timezone_s,
                                             platform='facebook'),
                'from': conv.sender,
                'me': conv.is_me,
            })
        # convs.reverse()
        context = {
            'pm_messages': convs,
            'conversation_id': conv_id,
            'pm_platform': platform,
            'pm_recipient_id': sender_id,
            'pm_reply_supported': True
        }
        if request.user_agent.is_pc:
            return render(request, 'dashboard.html', context=context)
        else:
            return render(request, 'dashboard_mobile.html', context=context)
    if platform.strip() == 'reddit':
        rcv = ConversationMessages.objects.filter(conversation_id=conv_id).order_by('created_at')
        for r in rcv:
            convs.append({
                'message': r.message,
                'date_sent': format_datetime(datetime_str=r.created_at, timezone_str=timezone_s, platform=platform),
                'from': r.sender,
                'me': r.is_me,

            })

        # convs.reverse()
        context = {
            'pm_messages': convs,
            'conversation_id': conv_id,
            'pm_platform': platform,
            'pm_reply_supported': False
        }
        if request.user_agent.is_pc:
            return render(request, 'dashboard.html', context=context)
        else:
            return render(request, 'dashboard_mobile.html', context=context)
    if platform.strip() == 'instagram':
        cp = Company.objects.filter(company_id=company_id).first()
        if not cp:
            return Response({'error': 'Bad request'})
        cfb = CompanyFacebook.objects.filter(company=cp).first()
        if not cfb:
            return Response({'error': 'Bad request'})
        cig = CompanyInstagram.objects.filter(company=cp).first()
        if not cig:
            return Response({'error': 'Bad request'})

        def getMesgs():
            url = f"https://graph.facebook.com/v21.0/{conv_id}"
            params = {"access_token": cfb.page_access_token, "fields": 'messages'}
            response = requests.get(url, params=params)
            msg_ids = response.json()['messages']['data']

            for msgd_id in msg_ids:
                msg_id = msgd_id['id']
                url = f"https://graph.facebook.com/v21.0/{msg_id}"
                params = {"access_token": cfb.page_access_token, "fields": 'id,created_time,from,to,message'}
                response = requests.get(url, params=params)
                dt = response.json()
                cnv = ConversationMessages.objects.filter(message_id=msg_id).first()
                frm_id = dt['from']['id']
                if not cnv:
                    cnv = ConversationMessages(
                        conversation_id=conv_id,
                        message_id=msg_id,
                        sender=dt['from']['username'],
                        message=dt['message'],
                        is_me=frm_id == cig.account_id,
                        created_at=datetime.strptime(dt['created_time'], "%Y-%m-%dT%H:%M:%S%z")
                    )
                    cnv.save()
                else:
                    cnv.message = dt['message']
                    cnv.save()

        igconmess = ConversationMessages.objects.filter(conversation_id=conv_id)
        if igconmess:
            igthrt = threading.Thread(target=getMesgs, daemon=True)
            igthrt.start()
        else:
            getMesgs()

        igconmess = ConversationMessages.objects.filter(conversation_id=conv_id).order_by('created_at')
        convs = []
        for igm in igconmess:
            convs.append({
                'message': igm.message,
                'date_sent': format_datetime(datetime_str=igm.created_at, timezone_str=timezone_s, platform='facebook'),
                'from': igm.sender,
                'me': igm.is_me,

            })
        # convs.reverse()
        context = {
            'pm_messages': convs,
            'conversation_id': conv_id,
            'pm_platform': platform,
            'pm_reply_supported': False
        }
        if request.user_agent.is_pc:
            return render(request, 'dashboard.html', context=context)
        else:
            return render(request, 'dashboard_mobile.html', context=context)
    return Response({'success': 'Bad request'})


@api_view(['POST', 'GET'])
def getPMs(request):
    company_id = request.POST.get('company_id', None)
    platform = request.POST.get('platform', None)
    timezone_s = request.POST.get('timezone', 'UTC')
    if not all([company_id, platform]):
        return Response({'error': 'Bad request'})
    if platform == 'reddit':
        cp = Company.objects.filter(company_id=company_id).first()
        if not cp:
            return Response({'error': 'Bad request'})
        cr = CompanyReddit.objects.filter(company=cp).first()
        if not cr:
            return Response({'error': 'Bad request'})
        senders = []

        def getconvs():
            reddit = praw.Reddit(
                client_id=settings.REDDIT_CLIENT_ID,
                client_secret=settings.REDDIT_CLIENT_SECRET,
                user_agent=settings.REDDIT_USER_AGENT,
                refresh_token=cr.refresh_token,
            )

            for message in reddit.inbox.messages():
                cnk = CompanyPrivateConversation.objects.filter(conversation_id=message.id).first()
                if not cnk:
                    cnk = CompanyPrivateConversation(
                        company=cp,
                        sender=message.author.name,
                        last_message_time=datetime.fromtimestamp(message.created_utc, tz=timezone.utc),
                        platform='reddit',
                        conversation_id=message.id,
                    )
                    cnk.save()
                    ccms = ConversationMessages(
                        conversation_id=message.id,
                        sender=message.author.name,
                        message=message.body,
                        is_me=message.author.name.lower() == cr.account_username,
                        created_at=datetime.fromtimestamp(message.created_utc, tz=timezone.utc)
                    )
                    ccms.save()
                else:
                    cnk = ConversationMessages.objects.filter(conversation_id=message.id).first()
                    cnk.message = message.body
                    cnk.save()

        cnc = CompanyPrivateConversation.objects.filter(platform='reddit', company=cp)
        if cnc:
            redTrt = threading.Thread(target=getconvs, daemon=True)
            redTrt.start()
        else:
            getconvs()

        cnc = CompanyPrivateConversation.objects.filter(platform='reddit', company=cp).order_by('-last_message_time')
        for cn in cnc:
            senders.append({
                'sender': cn.sender,
                'conv_id': cn.conversation_id,
                'platform': cn.platform,
                'updated_time': format_datetime(datetime_str=cn.last_message_time, timezone_str=timezone_s,
                                                platform=platform)
            })
        request.session['red_convos'] = senders
        context = {'senders': senders}
        if request.user_agent.is_pc:
            return render(request, 'dashboard.html', context=context)
        else:
            return render(request, 'dashboard_mobile.html', context=context)
    elif platform == 'facebook':
        cp = Company.objects.filter(company_id=company_id).first()
        if not cp:
            return Response({'error': 'Bad request'})
        cfb = CompanyFacebook.objects.filter(company=cp).first()
        if not cfb:
            return Response({'error': 'Bad request'})

        def getconvs():
            url = f"https://graph.facebook.com/v21.0/{cfb.page_id}/conversations"
            params = {"access_token": cfb.page_access_token, "fields": 'senders,id,updated_time',
                      'platform': 'messenger'}
            response = requests.get(url, params=params)
            conversations = response.json()['data']
            cpc = CompanyPrivateConversation.objects.filter(platform='facebook', company=cp)
            if cpc:
                for c in conversations:
                    sendr = c['senders']['data'][0]
                    cpk = cpc.filter(conversation_id=c['id']).first()
                    if not cpk:
                        utc_datetime = datetime.strptime(c['updated_time'], "%Y-%m-%dT%H:%M:%S%z")
                        cpk = CompanyPrivateConversation(
                            company=cp,
                            sender=sendr['name'],
                            sender_id=sendr['id'],
                            last_message_time=utc_datetime,
                            platform='facebook',
                            conversation_id=c['id']
                        )
                        cpk.save()
                    else:
                        cpk.sender_id = sendr['id']
                        cpk.save()
            else:
                for c in conversations:
                    sendr = c['senders']['data'][0]
                    utc_datetime = datetime.strptime(c['updated_time'], "%Y-%m-%dT%H:%M:%S%z")
                    cpc = CompanyPrivateConversation(
                        company=cp,
                        sender=sendr['name'],
                        sender_id=sendr['id'],
                        last_message_time=utc_datetime,
                        platform='facebook',
                        conversation_id=c['id']
                    )
                    cpc.save()

        conv = CompanyPrivateConversation.objects.filter(platform='facebook', company=cp)
        if conv:
            cnvThread = threading.Thread(target=getconvs, daemon=True)
            cnvThread.start()
        else:
            getconvs()
        senders = []
        conv = CompanyPrivateConversation.objects.filter(platform='facebook', company=cp).order_by('-last_message_time')
        for co in conv:
            senders.append({
                'sender': co.sender,
                'sender_id': co.sender_id,
                'conv_id': co.conversation_id,
                'platform': 'facebook',
                'updated_time': format_datetime(datetime_str=co.last_message_time, timezone_str=timezone_s,
                                                platform='facebook')
            })

        context = {'senders': senders}
        if request.user_agent.is_pc:
            return render(request, 'dashboard.html', context=context)
        else:
            return render(request, 'dashboard_mobile.html', context=context)
    elif platform == 'instagram':
        cp = Company.objects.filter(company_id=company_id).first()
        if not cp:
            return Response({'error': 'Bad request'})
        cfb = CompanyFacebook.objects.filter(company=cp).first()
        if not cfb:
            return Response({'error': 'Bad request'})
        cig = CompanyInstagram.objects.filter(company=cp).first()
        if not cig:
            return Response({'error': 'Bad request'})

        # url =f"https://graph.instagram.com/v21.0/me/conversations"
        def getconvs():
            url = f"https://graph.facebook.com/v21.0/{cfb.page_id}/conversations"
            params = {"access_token": cfb.page_access_token, "fields": 'ud,updated_time', 'platform': 'instagram'}
            response = requests.get(url, params=params)
            conversations = response.content
            # Print the response
            conversations = response.json()['data']

            def getSMes(con_id):
                url = f"https://graph.facebook.com/v21.0/{con_id}"
                params = {"access_token": cfb.page_access_token, "fields": 'messages'}
                response = requests.get(url, params=params)
                msg_id = response.json()['messages']['data'][0]['id']

                url = f"https://graph.facebook.com/v21.0/{msg_id}"
                params = {"access_token": cfb.page_access_token, "fields": 'id,created_time,from,to,message'}
                response = requests.get(url, params=params)
                dt = response.json()
                frm_uname = dt['from']['username']
                frm_id = dt['from']['id']
                to_uname = dt['to']['data'][0]['username']
                return frm_uname if frm_id != cig.account_id else to_uname

            for c in conversations:
                cnvmes = CompanyPrivateConversation.objects.filter(conversation_id=c['id']).first()
                if not cnvmes:
                    cnvmes = CompanyPrivateConversation(
                        company=cp,
                        sender=getSMes(c['id']),
                        last_message_time=datetime.strptime(c['updated_time'], "%Y-%m-%dT%H:%M:%S%z"),
                        platform='instagram',
                        conversation_id=c['id']
                    )
                    cnvmes.save()

        cpv = CompanyPrivateConversation.objects.filter(platform='instagram')
        if cpv:
            trd = threading.Thread(target=getconvs, daemon=True)
            trd.start()
        else:
            getconvs()
        senders = []
        conversations = CompanyPrivateConversation.objects.filter(platform='instagram', company=cp).order_by(
            '-last_message_time')
        for c in conversations:
            senders.append({
                'sender': c.sender,
                'conv_id': c.conversation_id,
                'platform': c.platform,
                'updated_time': format_datetime(datetime_str=c.last_message_time, timezone_str=timezone_s,
                                                platform='facebook')
            })
        context = {'senders': senders}
        if request.user_agent.is_pc:
            return render(request, 'dashboard.html', context=context)
        else:
            return render(request, 'dashboard_mobile.html', context=context)
    elif platform == 'chatbot':
        senders=[]
        cp = Company.objects.filter(company_id=company_id).first()
        if not cp:
            return Response({'error': 'Bad request'})

        conversations=CompanyBotChats.objects.filter(company=cp)
        for c in conversations:
            senders.append({
                'sender': c.sender,
                'conv_id': c.conversation_id,
                'platform': 'chatbot',
                'updated_time': format_datetime(datetime_str=c.date_sent, timezone_str=timezone_s,
                                                platform='chatbot')
            })
        context = {'senders': senders}
        if request.user_agent.is_pc:
            return render(request, 'dashboard.html', context=context)
        else:
            return render(request, 'dashboard_mobile.html', context=context)
    return Response({'error': 'Bad request'})
    

@api_view(['POST', 'GET'])
def companyReviews(request):
    company_id = request.POST.get('company_id', None)
    filters = request.POST.get('filters', [])
    review_id_publish = request.POST.get('review_id_publish', None)
    if not company_id:
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    if not filters:
        if review_id_publish:
            cpx=CompanyReviews.objects.filter(company=cp,id=review_id_publish).first()
            if cpx:
                cpx.is_published = not cpx.is_published
                cpx.save()
        cpr = CompanyReviews.objects.filter(company=cp)
    else:
        if review_id_publish:
            cpx=CompanyReviews.objects.filter(company=cp,id=review_id_publish).first()
            if cpx:
                cpx.is_published = not cpx.is_published
                cpx.save()

        filters = [i.lower() for i in filters.split(',')]

        cpr = CompanyReviews.objects.filter(company=cp)
        if 'published' in filters:
            cpr = cpr.filter(is_published=True)
        if 'not published' in filters:
            cpr = cpr.filter(is_published=False)
        if 'positive' in filters:
            cpr = cpr.filter(is_positive=True)
        if 'negative' in filters:
            cpr = cpr.filter(is_negative=True)
        if 'neutral' in filters:
            cpr = cpr.filter(is_neutral=True)
        platforms = []
        if 'facebook' in filters:
            platforms.append('facebook')
        if 'instagram' in filters:
            platforms.append('instagram')
        if 'tiktok' in filters:
            platforms.append('tiktok')
        if 'reddit' in filters:
            platforms.append('reddit')

        if platforms:
            cpr = cpr.filter(platform__in=platforms)
    reviews = []
    for r in cpr:
        reviews.append({
            'commentor': r.commentor,
            'content': r.content,
            'link': r.link,
            'published': r.is_published,
            'neutral': r.is_neutral,
            'positive': r.is_positive,
            'negative': r.is_negative,
            'date_commented': r.date_commented,
            'category': r.category,
            'platform': r.platform,
            'id': r.id
        })

    context = {
        'reviews': reviews
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


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
    
    trd=threading.Thread(target=get_user_location,daemon=True, kwargs={'request':request,'page':'dashboard'})
    trd.start()
    
    cm = Company.objects.filter(company_id=company_id).first()
    if not cm:
        return render(request, '404error.html')
    
    cfs=CompanyFileSizes.objects.filter(company=cm).first()
    if not cfs:
        alct=0
        if cm.company_free_trial:
            alct=524288000 
        elif cm.company_subscription_tier == 1:
            alct=1073741824
        elif cm.company_subscription_tier == 2:
            alct=10737418240
        elif cm.company_subscription_tier == 3:
            alct=107374182400
            
        cfs = CompanyFileSizes(
           company=cm,
           allocated=alct
        )
        cfs.save()
    
    if cm.company_review_link:
        bnm=cm.company_name.strip().replace(' ','-')
        current_url = f"{request.scheme}://{request.get_host()}/social-proof/"
        fin_link=current_url+bnm.lower()
        cm.company_review_link=fin_link
        cm.save()

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

        # get posts 
    upd_pst = threading.Thread(target=updatePosts, daemon=True, kwargs={
        'company_id': company_id,
    })
    upd_pst.start()

    fb_ig = request.session.get('facebook_ig_data', {})
    if fb_ig:
        ldta = fb_ig.get('time_updated')
        ldt = datetime.fromisoformat(ldta)
        df = (timezone.now() - ldt).total_seconds()
        if df > 18000:  # update after 6 hrs only
            try:
                if cig:
                    dt = get_instagram_account_insights(access_token=cig.long_lived_token,
                                                        instagram_account_id=cig.account_id, company_id=company_id)
                    cig.profile_url = dt['profile_picture_url']
                    fb_ig['time_updated'] = timezone.now().isoformat()
                    cig.save()
                if cfb:
                    dt = get_facebook_page_insights(access_token=cfb.page_access_token, page_id=cfb.page_id,
                                                    company_id=company_id)
                    cfb.profile_url = dt['p_picture']
                    fb_ig['time_updated'] = timezone.now().isoformat()
                    cfb.save()
            except:
                pass
    else:
        tk_data = {
            'time_updated': timezone.now().isoformat()
        }
        try:
            if cig:
                dt = get_instagram_account_insights(access_token=cig.long_lived_token,
                                                    instagram_account_id=cig.account_id, company_id=company_id)
                cig.profile_url = dt['profile_picture_url']
                print('saving profile url')
                cig.save()
            if cfb:
                dt = get_facebook_page_insights(access_token=cfb.page_access_token, page_id=cfb.page_id,
                                                company_id=company_id)
                cfb.profile_url = dt['p_picture']
                print('saving fb profile pic ')
                cfb.save()
            request.session['facebook_ig_data'] = tk_data
        except:
            pass
    dispts=[]
    for disp in CompanyTransactionDisputes.objects.filter(company=cm).order_by('-pk'):
        dispts.append({
            'title':disp.title,
            'description':disp.description,
            'date_sent':format_datetime(datetime_str=disp.date_sent, timezone_str=disp.timezone_str,
                                                 platform='-'),
        })
    transcts=CompanyTransactionHistory.objects.filter(company=cm).last()
    tx_hist=[]
    for th in CompanyTransactionHistory.objects.filter(company=cm).order_by('-pk'):
        tx_hist.append({
            'subscription_date':th.subscription_date.strftime("%d %b %Y"),
            'subscription_period':f'{datetime.fromisoformat(th.subscription_period['start_date']).strftime("%d %b %Y")} - { datetime.fromisoformat(th.subscription_period['end_date']).strftime("%d %b %Y")} ',
            'subscription_type':th.subscription_type.capitalize(),
            'subscription_amount':f'{th.subscription_currency} {th.subscription_amount}',
            'transaction_id':th.transaction_id,
            'sub_status':True if th.subscription_success else False,
            'subscription_notes':th.subscription_notes,
            'payer_email':th.payer_email
        })
        
    context = {
        'company_name': cm.company_name,
        'company_category': cm.company_category,
        'company_link': cm.company_link,
        'review_wall_link':cm.company_review_link,
        'company_enable_ai':cm.company_enable_ai,
        'company_show_page':cm.company_show_page,
        'company_profile':cpp.p_pic.url if cpp else 'https://pic.onlinewebfonts.com/thumbnails/icons_358304.svg' ,
        # 'company_profile': 'https://img.freepik.com/premium-vector/vector-logo-dance-club-that-says-dance-club_1107171-3823.jpg',
        'company_about': cm.company_about,
        'disputes':dispts,
        'transactions':tx_hist,
        'company_subs': {
            'subscription_active': cm.company_active_subscription,
            'subscription_type': cm.company_subscription,
            'free_trial': cm.company_free_trial,
            # 'free_trial_expired': True if exp_dif < 0 else False,
            'free_trial_expiry': exp_dif,
            'subscription_period':f'{datetime.fromisoformat(transcts.subscription_period['start_date']).strftime("%a %d %b %Y")} - { datetime.fromisoformat(transcts.subscription_period['end_date']).strftime("%a %d %b %Y")} ' if transcts else '-'
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
        'freqs': CompanyFeatureRequest.objects.filter(company=cm).order_by('-pk'),
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
            'linked': cr.linked if cr else False,
            'active': cr.active if cr else False,
            'comment_karma': cr.comment_karma if cr else '',
            'link_karma':cr.link_karma if cr else '',
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
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


def updatePosts(company_id):
    cp = Company.objects.filter(company_id=company_id).first()
    cpsts = CompanyPosts.objects.filter(company=cp)
    if cpsts:
        for cps in cpsts:
            platforms = cps.platforms
            for platform in platforms:
                if platform == 'reddit':
                    # update reddit posts
                    red_psts = CompanyRedditPosts.objects.filter(post_id=cps.post_id)
                    for red_p in red_psts:
                        dtn = timezone.now()
                        lupd = red_p.last_updated
                        t_diff = (dtn - lupd).total_seconds()
                        if t_diff < 300:  # update after 5 mins
                            continue
                        subs = red_p.subs
                        total_impressions = 0
                        total_comments = 0
                        for sub in subs:
                            submission_id = sub['id']
                            # Fetch the submission object using the ID
                            try:
                                submission = reddit.submission(id=submission_id)
                                sub['upvotes'] = submission.score
                                sub['comments'] = submission.num_comments
                                total_comments += submission.num_comments
                                sub['upvote_ratio'] = submission.upvote_ratio
                                sub['crossposts'] = submission.num_crossposts
                                total_impressions += (
                                        submission.num_crossposts + submission.score + submission.num_comments)
                                red_p.save()
                            except:
                                continue
                        cps.engagement_count = total_impressions
                        cps.comment_count = total_comments
                        cps.save()


@api_view(['POST'])
def fetchPosts(request):
    company_id = request.POST.get('company_id', None)
    timezne = request.POST.get('timezone', None)
    if not company_id:
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    target_timezone = pytz.timezone(timezne)
    cp = CompanyPosts.objects.filter(company=cp).order_by('-pk')
    all_posts = []
    if not cp:
        for p in cp:
            um = UploadedMedia.objects.filter(post=p)
            med = []
            for m in um:
                med.append({
                    'media_url': m.media.url,
                    'is_video': False
                })
            reds = []

            if 'reddit' in p.platforms:
                cr = CompanyRedditPosts.objects.filter(post_id=p.post_id)
                if cr:
                    for c in cr:
                        t_en = 0
                        t_com = 0
                        for k in c.subs:
                            if k['published']:
                                p_id = k['id']
                                submission = reddit.submission(id=p_id)
                                k['upvote_ratio'] = submission.upvote_ratio * 100
                                k['upvotes'] = submission.score
                                k['comments'] = submission.num_comments
                                k['crossposts'] = submission.num_crossposts
                                reds.append(k)

                                vlx = submission.score + submission.num_comments + submission.num_crossposts
                                t_en += vlx
                                t_com += submission.num_comments
                        p.comment_count = t_com
                        p.engagement_count = t_en
                        p.save()
                        c.save()

            eng_cnt = p.engagement_count
            if eng_cnt > 1000000:
                eng_cnt = round(eng_cnt / 1000000, 1)
            elif eng_cnt > 1000:
                eng_cnt = round(eng_cnt / 1000, 1)
            cmt_cnt = p.comment_count
            if cmt_cnt > 1000:
                cmt_cnt = round(cmt_cnt / 1000, 1)
            elif cmt_cnt > 1000:
                cmt_cnt = round(cmt_cnt / 1000, 1)
            upl_t=p.date_uploaded.astimezone(target_timezone).strftime('%d %b, %H:%M')
            sch_t=p.date_scheduled.astimezone(target_timezone).strftime('%d %b, %H:%M')
            
            all_posts.append({
                'platforms': [pl.capitalize() for pl in p.platforms],
                'title': p.title,
                'content': p.description,
                'is_uploaded': p.is_published,
                'is_scheduled': p.is_scheduled,
                'comment_count': cmt_cnt,
                'engagement_count': eng_cnt,
                'tags': p.tags,
                'has_media': p.has_media,
                'cover_image_link': p.media_thumbnail,
                'media': None if not p.has_media else UploadedMedia.objects.filter(post=p).first(),
                'date_uploaded_h': upl_t,
                'date_scheduled_h': sch_t,
                'media': med,
                'post_id': p.post_id,
                'has_all': len(p.platforms) == 4,
                'has_reddit': 'reddit' in p.platforms,
                'has_tiktok': 'tiktok' in p.platforms,
                'has_facebook': 'facebook' in p.platforms,
                'has_instagram': 'instagram' in p.platforms,
            })
    else:
        for p in cp:
            um = UploadedMedia.objects.filter(post=p)
            med = []
            for m in um:
                med.append({
                    'media_url': m.media.url,
                    'is_video': False
                })
            reds = []
            upl_t=p.date_uploaded.astimezone(target_timezone).strftime('%d %b, %H:%M')
            sch_t=p.date_scheduled.astimezone(target_timezone).strftime('%d %b, %H:%M')
            
            
            eng_cnt = p.engagement_count
            if eng_cnt > 1000000:
                eng_cnt = round(eng_cnt / 1000000, 1)
            elif eng_cnt > 1000:
                eng_cnt = round(eng_cnt / 1000, 1)
            cmt_cnt = p.comment_count
            if cmt_cnt > 1000:
                cmt_cnt = round(cmt_cnt / 1000, 1)
            elif cmt_cnt > 1000:
                cmt_cnt = round(cmt_cnt / 1000, 1)
            all_posts.append({
                'platforms': [pl.capitalize() for pl in p.platforms],
                'title': p.title,
                'content': p.description,
                'is_uploaded': p.is_published,
                'is_scheduled': p.is_scheduled,
                'is_published': p.is_published,
                'has_failed': p.has_failed,
                'comment_count': cmt_cnt,
                'engagement_count': eng_cnt,
                'tags': p.tags,  # if not p.tags else p.tags.split(),
                'has_media': p.has_media,
                'cover_image_link': p.media_thumbnail,
                'media': None if not p.has_media else UploadedMedia.objects.filter(post=p).first(),
                'date_uploaded_h':upl_t,
                'date_scheduled_h': sch_t,
                'media': med,
                'post_id': p.post_id,
                'has_all': len(p.platforms) == 4,
                'has_reddit': 'reddit' in p.platforms,
                'has_tiktok': 'tiktok' in p.platforms,
                'has_facebook': 'facebook' in p.platforms,
                'has_instagram': 'instagram' in p.platforms,

            })
        upd_pst = threading.Thread(target=updatePosts, daemon=True, kwargs={
            'company_id': company_id,
        })
        upd_pst.start()

    context = {
        'posts': all_posts,
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


# retrieve the stats of a given post
@api_view(['POST'])
def getStats(request):
    post_id = request.POST.get('post_id', None)
    if not post_id:
        return Response({'error': 'Bad request'})
    # get the post from the post_id
    pst = CompanyPosts.objects.filter(post_id=post_id).first()
    if not pst:
        return Response({'error': 'Bad request'})

    my_dict = {'Facebook': 0, 'Instagram': 0, 'Tiktok': 0, 'Reddit': 0}
    cr = CompanyRedditPosts.objects.filter(post_id=post_id).first()

    has_reddit = False
    red_up = []
    red_cmt = []
    red_cpst = []
    red_tteng = []
    red_subs = []
    red_te = 0
    fb_post_click = 0
    fb_impressions = 0
    impr_conv = 0

    if cr:
        print('reddit',cr.subs)
        has_reddit = True
        for c in cr.subs:
            k = c
            if k['published']:
                p_id = k['id']
                submission = reddit.submission(id=p_id)
                k['upvote_ratio'] = submission.upvote_ratio * 100
                k['upvotes'] = int(submission.score)
                k['comments'] = int(submission.num_comments)
                k['crossposts'] = int(submission.num_crossposts)
                red_subs.append(f"r/{k['sub_name']}")

                # vlx=submission.score+submission.num_comments+submission.num_crossposts
                # t_en+=vlx
                # t_com+=submission.num_comments

            red_up.append(c['upvotes'])
            red_tteng.append(c['upvote_ratio'])
            red_cmt.append(c['comments'])
            red_cpst.append(c['crossposts'])
        if red_tteng:
            red_te = sum(red_tteng) / len(red_tteng)
    total_reddit_en = sum(red_up) + sum(red_cmt) + sum(red_cpst)
    my_dict['Reddit'] = total_reddit_en
    has_facebook = False
    fb_video_data = {}
    cfb = CompanyFacebookPosts.objects.filter(post_id=post_id).first()
    if cfb:
        has_facebook = True
        cfbp = CompanyFacebook.objects.filter(company=pst.company).first()
        if not cfbp:
            print('No facebook object')
            return
        # get facebook insights
        url = f"https://graph.facebook.com/v21.0/{cfb.content_id}/insights"

        if pst.is_video:
            url = f"https://graph.facebook.com/v21.0/{cfb.content_id}/video_insights"
        '''
        Page Metrics
            page_post_engagements
            page_fan_adds_by_paid_non_paid_unique
            page_lifetime_engaged_followers_unique
            page_daily_follows
            page_daily_unfollows_unique
            page_follows
            page_impressions,page_impressions_unique,page_impressions_paid,
            page_impressions_viral,page_impressions_nonviral
            page_fans_locale,page_fans_city,page_fans_country
            page_fan_adds,page_fan_adds_unique,page_fan_removes
            page_fans_by_like_source
            page_views_total
            page_negative_feedback_by_type

        Post Metrics
            post_impressions,post_impressions_unique,post_impressions_paid,
            post_impressions_fan,post_impressions_organic  
            post_impressions_viral,post_impressions_nonviral
            post_reactions_by_type_total
            post_clicks
            **video**
            post_video_avg_time_watched
            post_video_complete_views_organic
            post_video_complete_views_organic_unique
            post_video_complete_views_paid
            post_video_complete_views_paid_unique
            post_video_retention_graph
            post_video_views_organic
            post_video_views_organic_unique
            post_video_views_paid
            post_video_views_paid_unique
            post_video_views
            post_video_views_unique
            post_video_views_autoplayed
            post_video_views_clicked_to_play
            post_video_views_sound_on
            post_video_view_time
            post_video_view_time_by_age_bucket_and_gender
            post_video_view_time_by_region_id
            post_video_view_time_by_country_id
            post_video_social_actions_count_unique
        Stories 
            post_activity_by_action_type   
        Video Ad Breaks
            page_daily_video_ad_break_ad_impressions_by_crosspost_status
            page_daily_video_ad_break_cpm_by_crosspost_status
            page_daily_video_ad_break_earnings_by_crosspost_status
            post_video_ad_break_ad_impressions
            post_video_ad_break_earnings
            post_video_ad_break_ad_cpm
            creator_monetization_qualified_views

        Page Video Metrics
            page_video_views,page_video_views_paid,page_video_views_organic,page_video_views_autoplayed,
            page_video_repeat_views,page_video_complete_views_30s,page_video_complete_views_30s_paid
            page_video_complete_views_30s_organic,page_video_complete_views_30s_autoplayed,
            page_video_complete_views_30s_click_to_play,page_video_complete_views_30s_unique
            page_video_complete_views_30s_repeat_views,post_video_complete_views_30s_autoplayed
            post_video_complete_views_30s_clicked_to_play,
            page_video_view_time
        '''
        if pst.is_video:
            params = {
                "access_token": cfbp.page_access_token,
            }
            response = requests.get(url, params=params)
            if response.status_code == 200:
                vl = response.json().get('data')
                # for metric in vid_metric:
                clck = 0
                impr = 0
                for v in vl:
                    print(v['name'])
                    vl = v['values'][0]['value']
                    if v['name'] == 'total_video_views_autoplayed':
                        clck += vl
                    if v['name'] == 'total_video_views_clicked_to_play':
                        clck += vl
                    if v['name'] == 'total_video_impressions':
                        impr = vl
                    cfb.post_impression_type[v['name']] = vl
                    cfb.save()
                # save video data
                cfb.impression_count = clck
                cfb.impression_count = impr
                cfb.save()
                fb_post_click = cfb.post_clicks
                fb_impressions = cfb.impression_count
                if cfb.impression_count > 0:
                    impr_conv = cfb.post_clicks / cfb.impression_count

            else:
                print('failed', response.status_code, response.content)
                return Response({'success': True})

        else:
            params = {
                "metric": "post_clicks,post_impressions,post_impressions_viral,post_impressions_unique,post_impressions_paid,post_impressions_fan,post_impressions_organic,post_impressions_nonviral",
                "access_token": cfbp.page_access_token,
            }
            response = requests.get(url, params=params)
            if response.status_code == 200:
                vl = response.json()['data']
                for v in vl:
                    if v['name'] == 'post_clicks':
                        vl = v['values'][0]['value']
                        cfb.post_impression_type['post_clicks'] = vl
                        cfb.post_clicks = vl
                        cfb.save()
                    if v['name'] == 'post_impressions_viral':
                        vl = v['values'][0]['value']
                        cfb.post_impression_type['post_impressions_viral'] = vl
                        cfb.save()
                    if v['name'] == 'post_impressions_unique':
                        vl = v['values'][0]['value']
                        cfb.post_impression_type['post_impressions_unique'] = vl
                        cfb.save()
                    if v['name'] == 'post_impressions_paid':
                        vl = v['values'][0]['value']
                        cfb.post_impression_type['post_impressions_paid'] = vl
                        cfb.save()
                    if v['name'] == 'post_impressions_fan':
                        vl = v['values'][0]['value']
                        cfb.post_impression_type['post_impressions_fan'] = vl
                        cfb.save()
                    if v['name'] == 'post_impressions_organic':
                        vl = v['values'][0]['value']
                        cfb.post_impression_type['post_impressions_organic'] = vl
                        cfb.save()
                    if v['name'] == 'post_impressions_nonviral':
                        vl = v['values'][0]['value']
                        cfb.post_impression_type['post_impressions_nonviral'] = vl
                        cfb.save()
                    if v['name'] == 'post_impressions':
                        vl = v['values'][0]['value']
                        my_dict['facebook'] = vl
                        cfb.post_impression_type['post_impressions'] = vl
                        cfb.impression_count = vl
                        cfb.save()

                # cfb.impression_count=''
                fb_post_click = cfb.post_clicks
                fb_impressions = cfb.impression_count
                if cfb.impression_count > 0:
                    impr_conv = cfb.post_clicks / cfb.impression_count
                # print("metrics retrieved successfully:", response.json())
            else:
                print("Error getting metrics:", response.json())
    impress = {}
    if cfb:
        dts = cfb.post_impression_type
        if pst.is_video:
            if dts['total_video_impressions'] > 0 or dts['total_video_play_count'] > 0:
                impress = {
                    'impression_fans': dts['total_video_impressions_fan'],
                    'impression_uniques': dts['total_video_impressions_unique'],
                    'impression_paid': dts['total_video_impressions_paid'],
                    'impression_organic': dts['total_video_impressions_organic'],
                    'impression_viral': dts['total_video_impressions_viral'],
                    'impression_nonviral': 0,
                    'has_data': True
                }
                cfb.impression_count = dts['total_video_impressions']
                cfb.post_clicks = dts['total_video_complete_views']
                cfb.save()

                awt = dts['total_video_avg_time_watched'] / 1000
                if awt > 3600:
                    awt = f'{round(awt / 3600, 2)}h'
                elif awt > 60:
                    awt = f'{round(awt / 60, 2)}m'
                else:
                    awt = f'{round(awt, 2)}s'

                twt = dts['total_video_view_total_time'] / 1000
                if twt > 3600:
                    twt = f'{round(twt / 3600, 2)}h'
                elif twt > 60:
                    twt = f'{round(twt / 60, 2)}m'
                else:
                    twt = f'{round(twt, 2)}s'
                my_dict['facebook'] = dts['total_video_impressions']
                country_keys = []
                country_values = []
                if dts['total_video_view_time_by_country_id']:
                    pass

                age_values = []
                age_keys = ['13-17', '18-24', '25-34', '35-44', '45-54', '54-64', '65+']
                if dts['total_video_view_time_by_age_bucket_and_gender']:
                    age_values = [{
                        'name': 'Male',
                        'data': [44, 55, 41, 64, 22, 43, 21]
                    }, {
                        'name': 'Female',
                        'data': [53, 32, 33, 52, 13, 44, 32]
                    }]
                    age_keys = ['13-17', '18-24', '25-34', '35-44', '45-54', '54-64', '65+']
                video_retention_labels = []
                video_retention_data = []
                if dts['total_video_retention_graph']:
                    vrv = dts['total_video_retention_graph'].keys()
                    video_retention_labels = [f"{i}'" for i in vrv]
                    vd = dts['total_video_retention_graph'].values()
                    video_retention_data = [round(i * 100, 1) for i in vd]

                if cfb.impression_count > 0:
                    impr_conv = cfb.post_clicks / cfb.impression_count

                # print(dts['total_video_retention_graph'])   
                fb_video_data = {
                    'video_play_count': dts['total_video_play_count'],
                    'average_watch_time': awt,
                    'total_watch_time': twt,
                    'total_video_retention_graph': dts['total_video_retention_graph'],
                    'video_retention_labels': video_retention_labels,
                    'video_retention_data': video_retention_data,
                    'total_video_consumption_rate': dts['total_video_consumption_rate'],
                    'total_views': dts['total_video_complete_views'],
                    'organic_views': dts['total_video_complete_views_organic'],
                    'paid_views': dts['total_video_complete_views_paid'],
                    'viewers_countries': [] if not dts['total_video_view_time_by_country_id'] else dts[
                        'total_video_view_time_by_country_id'],
                    'country_keys': country_keys,
                    'country_values': country_values,
                    'age_keys': age_keys,
                    'age_values': age_values,
                    'age_gender': [] if not dts['total_video_view_time_by_age_bucket_and_gender'] else dts[
                        'total_video_view_time_by_age_bucket_and_gender']
                }
            else:
                impress = {
                    'impression_fans': None,
                    'impression_uniques': None,
                    'impression_paid': None,
                    'impression_organic': None,
                    'impression_viral': None,
                    'impression_nonviral': None,
                }
                impress['has_data'] = False

        else:
            impress = {
                'impression_fans': dts['post_impressions_fan'],
                'impression_uniques': dts['post_impressions_unique'],
                'impression_paid': dts['post_impressions_paid'],
                'impression_organic': dts['post_impressions_organic'],
                'impression_viral': dts['post_impressions_viral'],
                'impression_nonviral': dts['post_impressions_nonviral'],
                'has_data': True
            }

    sorted_dict = dict(sorted(my_dict.items(), key=lambda item: item[1], reverse=True))
    return Response({'result': 'success',
                     'has_reddit': has_reddit,
                     'reddit_total_engagement': f'{red_te}%',
                     'reddit_upvotes': red_up,
                     'reddit_comments': red_cmt,
                     'reddit_crossposts': red_cpst,
                     'reddit_subs': red_subs,
                     'platform_engagement': list(sorted_dict.values()),
                     'pltfrms': list(sorted_dict.keys()),
                     #  facebook
                     'fb_impressions': fb_impressions,
                     'fb_clicks': fb_post_click,
                     'has_facebook': has_facebook,
                     'fb_conversion_rate': f'{round(impr_conv * 100, 1)}%' if impr_conv > 0 else impr_conv,
                     'is_media_video': pst.is_video,
                     'impression_dist': impress,
                     'fb_video_data': fb_video_data
                     })


def processCommentReplies(comment_id, replies, submission_op):
    for comment in replies:
        cmr = CompanyPostsCommentsReplies.objects.filter(comment_id=comment.id).first()
        if not cmr:
            if not all([comment.author]):
                continue
            cpstcmt = CompanyPostsCommentsReplies(
                parent_comment_id=comment_id,
                comment_id=comment.id,
                is_op=comment.author == submission_op,
                author=comment.author if comment.author else '[Deleted]',
                author_profile=comment.author.icon_img if comment.author else None,
                message=comment.body,
                like_count=comment.score,
                reply_count=len(comment.replies),
                date_updated=datetime.fromtimestamp(comment.created_utc)
            )
            cpstcmt.save()
        else:
            if comment.body == '[deleted]':
                cmr.delete()
                continue
            cmr.message = comment.body
            cmr.like_count = comment.score
            cmr.reply_count = len(comment.replies)
            cmr.save()
        if len(comment.replies) > 0:
            # nested reply recursive
            processCommentReplies(comment_id=comment.id, replies=comment.replies, submission_op=submission_op)


def fetchRedditComments(post, post_id):
    crp = CompanyRedditPosts.objects.filter(post_id=post_id).first()
    if crp:
        platform = 'reddit'
        for sbs in crp.subs:
            p_id = sbs['id']
            submission = reddit.submission(id=p_id)
            # Ensure comments are fully loaded
            submission.comments.replace_more(limit=None)
            submission_op = submission.author
            # Iterate over the comments
            for comment in submission.comments:
                cmt = CompanyPostsComments.objects.filter(comment_id=comment.id).first()
                if not cmt:
                    cpstcmt = CompanyPostsComments(
                        post=post,
                        comment_id=comment.id,
                        is_op=comment.author == submission_op,
                        platform=platform,
                        author=comment.author,
                        author_profile=comment.author.icon_img,
                        message=comment.body,
                        like_count=comment.score,
                        reply_count=len(comment.replies),
                        date_updated=datetime.fromtimestamp(comment.created_utc)
                    )
                    cpstcmt.save()
                else:
                    cmt.message = comment.body
                    cmt.like_count = comment.score
                    cmt.reply_count = len(comment.replies)
                    cmt.save()
                # recursively process comment replies using threads
                if len(comment.replies) > 0:
                    # save the reply comments
                    processCommentReplies(comment_id=comment.id, replies=comment.replies, submission_op=submission_op)


def processFacebookReplies(comment_id, page_access_token, page_id):
    print('Get facebook replies')
    url = f"https://graph.facebook.com/v21.0/{comment_id}/comments"
    params = {
        'fields': 'id,message,from{id,name,picture},created_time,like_count,comment_count',
        'access_token': page_access_token
    }
    response = requests.get(url, params=params)

    if response.status_code == 200:
        val = response.json()
        datas = val['data']
        for data in datas:
            created_time_str = data['created_time']
            created_time_naive = datetime.strptime(created_time_str, "%Y-%m-%dT%H:%M:%S%z")

            created_time_with_timezone = created_time_naive.astimezone(timezone.utc)
            cpr = CompanyPostsCommentsReplies.objects.filter(comment_id=data['id']).first()
            if not cpr:
                cpr = CompanyPostsCommentsReplies(
                    parent_comment_id=comment_id,
                    comment_id=data['id'],
                    author=data['from']['name'],
                    message=data['message'],
                    author_profile=data['from']['picture']['data']['url'],
                    is_op=data['from']['id'] == page_id,
                    like_count=data['like_count'],
                    reply_count=data['comment_count'],
                    is_published=True,
                    date_updated=created_time_with_timezone
                )
                cpr.save()
            else:
                cpr.message = data['message']
                cpr.like_count = data['like_count']
                cpr.reply_count = data['comment_count']
                cpr.save()
            if cpr.reply_count > 0:
                # fetch reply to reply
                print('fetching reply to the reply')
                processFacebookReplies(comment_id=data['id'], page_access_token=page_access_token, page_id=page_id)


    else:
        print('error found')
        raise Exception(f"Error fetching data: {response.status_code} - {response.text}")


def fetchFacebookComments(post, post_id):
    print('Fetching facebook comments')
    cfbp = CompanyFacebookPosts.objects.filter(post_id=post_id).first()
    if cfbp:
        platform = 'facebook'
        cfb = CompanyFacebook.objects.filter(company=post.company).first()
        if not cfb:
            return
        # Fields to fetch
        url = f'https://graph.facebook.com/v21.0/{cfbp.content_id}/comments'
        FIELDS = (
            'id,message,from{id,name,picture},created_time,comment_count,like_count'
        )
        params = {
            'fields': FIELDS,
            'access_token': cfb.page_access_token
        }
        response = requests.get(url, params=params)

        if response.status_code == 200:
            val = response.json()
            data = val['data']
            for d in data:
                c_id = d['id']
                created_time_str = d['created_time']
                created_time_naive = datetime.strptime(created_time_str, "%Y-%m-%dT%H:%M:%S%z")

                created_time_with_timezone = created_time_naive.astimezone(timezone.utc)
                cpc = CompanyPostsComments.objects.filter(comment_id=c_id).first()
                if not cpc:
                    cpc = CompanyPostsComments(
                        post=post,
                        comment_id=c_id,
                        platform=platform,
                        author=d['from']['name'],
                        message=d['message'],
                        author_profile=d['from']['picture']['data']['url'],
                        is_op=d['from']['id'] == cfb.page_id,
                        like_count=d['like_count'],
                        reply_count=d['comment_count'],
                        is_published=True,
                        date_updated=created_time_with_timezone
                    )
                    cpc.save()
                else:
                    cpc.like_count = d['like_count']
                    cpc.reply_count = d['comment_count']
                    cpc.date_updated = created_time_with_timezone
                    cpc.save()
                print('reply count', cpc.reply_count)
                if cpc.reply_count > 0:
                    # process the replies
                    processFacebookReplies(comment_id=c_id, page_access_token=cfb.page_access_token,
                                           page_id=cfb.page_id)
        else:
            raise Exception(f"Error fetching data: {response.status_code} - {response.text}")


def fetchInstagramComments(post, post_id):
    pass


def fetchTiktokComments(post, post_id):
    pass


def commentBackgroundUpdate(post, post_id):
    rdCmtThread = threading.Thread(target=fetchRedditComments, daemon=True, kwargs={
        'post_id': post_id,
        'post': post
    })
    rdCmtThread.start()

    fbCmtThread = threading.Thread(target=fetchFacebookComments, daemon=True, kwargs={
        'post_id': post_id,
        'post': post
    })
    fbCmtThread.start()


@api_view(['POST'])
def likeComment(request):
    comment_id = request.POST.get('comment_id', None)
    comment_level = request.POST.get('comment_level', None)
    company_id = request.POST.get('company_id', None)
    if not all([comment_id, comment_id, comment_level]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    # get the specific platform
    pltform = ''
    if comment_level == 'comment_post':
        cpst = CompanyPostsComments.objects.filter(comment_id=comment_id).first()
        if cpst:
            pltform = cpst.platform
    elif comment_level == 'comment_sec_reply':
        cprs = CompanyPostsCommentsReplies.objects.filter(comment_id=comment_id).first()
        if cprs:
            pr_id = cprs.parent_comment_id
            cprs = CompanyPostsCommentsReplies.objects.filter(comment_id=pr_id).first()
            if cprs:
                pr_id = cprs.parent_comment_id
                cpst = CompanyPostsComments.objects.filter(comment_id=pr_id).first()
                if cpst:
                    pltform = cpst.platform
    else:
        cprs = CompanyPostsCommentsReplies.objects.filter(comment_id=comment_id).first()
        if cprs:
            pr_id = cprs.parent_comment_id
            cpst = CompanyPostsComments.objects.filter(comment_id=pr_id).first()
            if cpst:
                pltform = cpst.platform
    print(pltform)
    if not pltform:
        return Response({'error': 'Bad request'})
    if pltform == 'reddit':
        print('upvoting reddit post')
        try:
            cr = CompanyReddit.objects.filter(company=cp).first()
            reddit = praw.Reddit(
                client_id=settings.REDDIT_CLIENT_ID,
                client_secret=settings.REDDIT_CLIENT_SECRET,
                user_agent=settings.REDDIT_USER_AGENT,
                refresh_token=cr.refresh_token,
            )
            comment = reddit.comment(id=comment_id)  # Replace with the comment ID
            # Upvote the comment
            comment.upvote()
            return Response({'success': 'Bad request'})
        except:
            return Response({'error': 'Could not upvote comment'})
    if pltform == 'facebook':
        cfb = CompanyFacebook.objects.filter(company=cp).first()
        if not cfb:
            print('no facebook account')
            return Response({'error': 'Could not like comment'})

        url = f"https://graph.facebook.com/v21.0/{comment_id}/likes"
        params = {
            "access_token": cfb.page_access_token
        }
        try:
            response = requests.post(url, params=params)
            response.raise_for_status()  # Raise an error for HTTP error codes
            data = response.json()
            if data.get("success"):
                print("Comment liked successfully!")
                return Response({'success': 'comment liked'})
            else:
                return Response({'error': 'Could not like comment'})
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return Response({'error': 'Could not like comment'})


# Example usage

@api_view(['POST'])
def getComments(request):
    post_id = request.POST.get('post_id', None)
    if not post_id:
        return Response({'error': 'Bad request'})
    # get the ost from the post_id
    pst = CompanyPosts.objects.filter(post_id=post_id).first()
    if not pst:
        return Response({'error': 'Bad request'})
    # try:
    cpstcmt = CompanyPostsComments.objects.filter(post=pst)
    if not cpstcmt:
        # reddit post comments
        crp = CompanyRedditPosts.objects.filter(post_id=post_id).first()
        if crp:
            fetchRedditComments(post=pst, post_id=post_id)
        cfbp = CompanyFacebookPosts.objects.filter(post_id=post_id).first()
        if cfbp:
            fetchFacebookComments(post=pst, post_id=post_id)
    else:
        # return already present comments while updating in the background
        thrd = threading.Thread(target=commentBackgroundUpdate, daemon=True, kwargs={
            'post': pst,
            'post_id': post_id,
        })
        thrd.start()

    cpstmt = CompanyPostsComments.objects.filter(post=pst).order_by('-like_count', '-reply_count', '-pk')
    cmts = []
    for cpm in cpstmt:
        cmts.append({
            'author': cpm.author,
            'id': cpm.comment_id,
            'author_profile': cpm.author_profile,
            'message_body': cpm.message,
            'isOP': cpm.is_op,
            'isReddit': True if cpm.platform == 'reddit' else False,
            'isFacebook': True if cpm.platform == 'facebook' else False,
            'isInstagram': True if cpm.platform == 'instagram' else False,
            'isTiktok': True if cpm.platform == 'tiktok' else False,
            'like_count': cpm.like_count,
            'reply_count': cpm.reply_count,
            'isPublished': cpm.is_published,
            'date_updated': cpm.date_updated

        })
        # cp=CompanyPosts.objects.all().order_by('-pk') # Execution time 4.7885 seconds
    cp = CompanyPosts.objects.filter(id=pst.id)  # Execution time 4.0257 seconds 
    all_posts = []
    for p in cp:
        um = UploadedMedia.objects.filter(post=p)
        med = []
        for m in um:
            med.append({
                'media_url': m.media.url,
                'is_video': False
            })
        reds = []
        cover_image_link = ''

        # if 'reddit' in p.platforms:
        #     cr = CompanyRedditPosts.objects.filter(post_id=p.post_id).first()
            # use threading to update post and comments
            # pass
        eng_cnt = p.engagement_count
        if eng_cnt > 1000000:
            eng_cnt = round(eng_cnt / 1000000, 1)
        elif eng_cnt > 1000:
            eng_cnt = round(eng_cnt / 1000, 1)
        cmt_cnt = p.comment_count
        if cmt_cnt > 1000:
            cmt_cnt = round(cmt_cnt / 1000, 1)
        elif cmt_cnt > 1000:
            cmt_cnt = round(cmt_cnt / 1000, 1)
        all_posts.append({
            'platforms': [pl.capitalize() for pl in p.platforms],
            'title': p.title,
            'content': p.description,
            'is_uploaded': p.is_published,
            'is_scheduled': p.is_scheduled,
            'comment_count': cmt_cnt,
            'engagement_count': eng_cnt,
            'tags': p.tags,
            'has_media': p.has_media,
            'cover_image_link': p.media_thumbnail,
            'media': None if not p.has_media else UploadedMedia.objects.filter(post=p).first(),
            'date_uploaded': p.date_uploaded,
            'date_scheduled': p.date_scheduled,
            'media': med,
            'post_id': p.post_id,
            'has_all': len(p.platforms) == 4,
            'has_reddit': 'reddit' in p.platforms,
            'has_tiktok': 'tiktok' in p.platforms,
            'has_facebook': 'facebook' in p.platforms,
            'has_instagram': 'instagram' in p.platforms,
        })

    context = {
        'success': True,
        'comments_data': cmts,
        'posts': all_posts,
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


@api_view(['POST'])
def getCommentReplies(request):
    c_id = request.POST.get('comment_id', None)
    if not c_id:
        return Response({'error': 'Bad request'})

    pstc = CompanyPostsComments.objects.filter(comment_id=c_id).first()
    if not pstc:
        return Response({'error': 'Bad request'})
    #  get the replies to this comment
    pst = pstc.post
    c_replies = []
    crp = CompanyPostsCommentsReplies.objects.filter(parent_comment_id=c_id).order_by('-like_count', '-reply_count',
                                                                                      '-pk')
    for cpm in crp:
        replies = []
        crps = CompanyPostsCommentsReplies.objects.filter(parent_comment_id=cpm.comment_id).order_by('-like_count',
                                                                                                     '-reply_count',
                                                                                                     '-pk')
        for c_s in crps:
            replies.append({
                'author': c_s.author,
                'id': c_s.comment_id,
                'author_profile': c_s.author_profile,
                'message_body': c_s.message,
                'isOP': c_s.is_op,
                'like_count': c_s.like_count,
                'reply_count': c_s.reply_count,
                'isPublished': c_s.is_published,
                'date_updated': c_s.date_updated,
            })
        c_replies.append({
            'author': cpm.author,
            'id': cpm.comment_id,
            'author_profile': cpm.author_profile,
            'message_body': cpm.message,
            'isOP': cpm.is_op,
            'like_count': cpm.like_count,
            'reply_count': cpm.reply_count,
            'isPublished': cpm.is_published,
            'date_updated': cpm.date_updated,
            'replies': replies
        })
    # return that post alone
    # cp=CompanyPosts.objects.all().order_by('-pk')
    cp = CompanyPosts.objects.filter(id=pst.id)
    all_posts = []
    for p in cp:
        um = UploadedMedia.objects.filter(post=p)
        med = []
        for m in um:
            med.append({
                'media_url': m.media.url,
                'is_video': False
            })
        reds = []
        cover_image_link = ''

        if 'reddit' in p.platforms:
            cr = CompanyRedditPosts.objects.filter(post_id=p.post_id).first()
            # use threading to update post and comments
            pass
        eng_cnt = p.engagement_count
        if eng_cnt > 1000000:
            eng_cnt = round(eng_cnt / 1000000, 1)
        elif eng_cnt > 1000:
            eng_cnt = round(eng_cnt / 1000, 1)
        cmt_cnt = p.comment_count
        if cmt_cnt > 1000:
            cmt_cnt = round(cmt_cnt / 1000, 1)
        elif cmt_cnt > 1000:
            cmt_cnt = round(cmt_cnt / 1000, 1)
        all_posts.append({
            'platforms': [pl.capitalize() for pl in p.platforms],
            'title': p.title,
            'content': p.description,
            'is_uploaded': p.is_published,
            'is_scheduled': p.is_scheduled,
            'comment_count': cmt_cnt,
            'engagement_count': eng_cnt,
            'tags': p.tags,
            'has_media': p.has_media,
            'cover_image_link': p.media_thumbnail,
            'media': None if not p.has_media else UploadedMedia.objects.filter(post=p).first(),
            'date_uploaded': p.date_uploaded,
            'date_scheduled': p.date_scheduled,
            'media': med,
            'post_id': p.post_id,
            'has_all': len(p.platforms) == 4,
            'has_reddit': 'reddit' in p.platforms,
            'has_tiktok': 'tiktok' in p.platforms,
            'has_facebook': 'facebook' in p.platforms,
            'has_instagram': 'instagram' in p.platforms,
        })
    cpstmt = CompanyPostsComments.objects.filter(post=pst, comment_id=c_id)  # get only relevant comment optimise speed
    cmts = []
    for cpm in cpstmt:
        cmts.append({
            'author': cpm.author,
            'id': cpm.comment_id,
            'author_profile': cpm.author_profile,
            'message_body': cpm.message,
            'isOP': cpm.is_op,
            'isReddit': True if cpm.platform == 'reddit' else False,
            'isFacebook': True if cpm.platform == 'facebook' else False,
            'isInstagram': True if cpm.platform == 'instagram' else False,
            'isTiktok': True if cpm.platform == 'tiktok' else False,
            'like_count': cpm.like_count,
            'reply_count': cpm.reply_count,
            'isPublished': cpm.is_published,
            'date_updated': cpm.date_updated,

        })

    context = {
        'success': True,
        'comments_replies': c_replies,
        'comments_data': cmts,
        'posts': all_posts,
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)

@api_view(['POST','GET'])
def socialProof(request,company_name):
    cmn=company_name.replace('-',' ')
    cp=None
    for cpy in Company.objects.all():
        if cpy.company_name.strip().lower()==cmn:
            if cpy.company_show_page:
                cp=cpy
                break
    all_cp=[]
    cpo=Company.objects.all()
    
    for c in cpo:
        if c.company_name.lower().strip() == company_name.lower().strip():
            cp=c
        if c.company_show_page:
            all_cp.append(c.company_name)
    if not cp:
        context = {
            'success': False,
            'status':404,
            'search_autofill':json.dumps(all_cp),
            'company': company_name,
        }
        return render(request, 'review.html', context=context)
    sc = CompanyContacts.objects.filter(company=cp).first()
    eml=sc.email if sc else False
    revs=[]
    crevs=CompanyReviews.objects.filter(company=cp,is_published=True)
    for r in crevs:
        revs.append({
            'reviewer':r.commentor,
            'reviewer_profile':r.commentor_profile,
            'date_reviewed':r.date_commented.strftime('%d-%m-%Y'),
            'body':r.content,
            'platform':r.platform.capitalize(),
            'link':r.link
        })
    context = {
        'success': True,
        'search_autofill':json.dumps(all_cp),
        'about':cp.company_about,
        'phone':cp.company_phone,
        'email':eml if str(eml)!='None' else '' ,
        'company_address': {
            'address': cp.company_address,
            'zip': cp.zipcode,
            'city': cp.city,
            'state': cp.state,
            'country': cp.country
        },
        'website':cp.company_website,
        'company_socials': {
            'instagram': sc.instagram if sc else None,
            'facebook': sc.facebook if sc else None,
            'twitter': sc.twitter if sc else None,
            'linkedin': sc.linkedin if sc else None,
            'email': sc.email if sc else None,
            'whatsapp': sc.whatsapp if sc else None,
            'youtube': sc.youtube if sc else None,
            'tiktok': sc.tiktok if sc else None,
        },
        'reviews':revs,
        'company': company_name,
        'company_category':cp.company_category
    }

    return render(request, 'review.html', context=context)

@api_view(['POST'])
def postComment(request):
    comment_id = request.POST.get('comment_id', None)
    post_id = request.POST.get('post_id', None)
    comment_level = request.POST.get('comment_level', None)
    comment_rt = request.POST.get('comment', None)
    company_id = request.POST.get('company_id', None)
    if not all([comment_id, comment_rt, comment_id, comment_level]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})

    # get the specific platform
    # post_id=''
    pltform = ''
    if comment_level == 'comment-post':
        cpst = CompanyPostsComments.objects.filter(comment_id=comment_id).first()
        if cpst:
            pltform = cpst.platform
            # cps=cpst.post
            # post_id=cps.post_id
    else:
        cprs = CompanyPostsCommentsReplies.objects.filter(comment_id=comment_id).first()
        if cprs:
            pr_id = cprs.parent_comment_id
            cpst = CompanyPostsComments.objects.filter(comment_id=pr_id).first()
            if cpst:
                pltform = cpst.platform
                # cps=cpst.post
                # post_id=cps.post_id

    if not pltform:
        return Response({'error': 'Bad request'})
    if not post_id:
        print('cant get post id')
        return Response({'error': 'Bad request'})
    # try:
    if pltform == 'reddit':
        cr = CompanyReddit.objects.filter(company=cp).first()
        reddit = praw.Reddit(
            client_id=settings.REDDIT_CLIENT_ID,
            client_secret=settings.REDDIT_CLIENT_SECRET,
            user_agent=settings.REDDIT_USER_AGENT,
            refresh_token=cr.refresh_token,
        )
        comment = reddit.comment(id=comment_id)
        # Submit a reply
        comment.reply(comment_rt)
        # fetch comments 

    elif pltform == 'facebook':
        cfb = CompanyFacebook.objects.filter(company=cp).first()
        url = f"https://graph.facebook.com/v21.0/{comment_id}/comments"
        data = {
            'message': comment_rt,
            'access_token': cfb.page_access_token
        }
        response = requests.post(url, data=data)

        if response.status_code == 200:
            data = response.json()  # Returns the reply ID
        else:
            return Response({'error': 'Could not submit comment'})

    # get the post from the post_id
    pst = CompanyPosts.objects.filter(post_id=post_id).first()
    if not pst:
        return Response({'error': 'Bad request'})
    # try:
    print('thread started')
    if pltform == 'facebook':
        fetchFacebookComments(post=pst, post_id=post_id)
    elif pltform == 'tiktok':
        fetchTiktokComments(post=pst, post_id=post_id)
    elif pltform == 'instagram':
        fetchInstagramComments(post=pst, post_id=post_id)
    elif pltform == 'reddit':
        fetchRedditComments(post=pst, post_id=post_id)

    # wait until update has been collected

    cpstmt = CompanyPostsComments.objects.filter(post=pst).order_by('-like_count', '-reply_count', '-pk')
    cmts = []
    for cpm in cpstmt:
        cmts.append({
            'author': cpm.author,
            'id': cpm.comment_id,
            'author_profile': cpm.author_profile,
            'message_body': cpm.message,
            'isOP': cpm.is_op,
            'isReddit': True if cpm.platform == 'reddit' else False,
            'isFacebook': True if cpm.platform == 'facebook' else False,
            'isInstagram': True if cpm.platform == 'instagram' else False,
            'isTiktok': True if cpm.platform == 'tiktok' else False,
            'like_count': cpm.like_count,
            'reply_count': cpm.reply_count,
            'isPublished': cpm.is_published,
            'date_updated': cpm.date_updated

        })
        # cp=CompanyPosts.objects.all().order_by('-pk') # Execution time 4.7885 seconds

    cp = CompanyPosts.objects.filter(id=pst.id)  # Execution time 4.0257 seconds 
    all_posts = []
    for p in cp:
        um = UploadedMedia.objects.filter(post=p)
        med = []
        for m in um:
            med.append({
                'media_url': m.media.url,
                'is_video': False
            })
        reds = []
        cover_image_link = ''

        if 'reddit' in p.platforms:
            cr = CompanyRedditPosts.objects.filter(post_id=p.post_id).first()
            # use threading to update post and comments
            pass
        eng_cnt = p.engagement_count
        if eng_cnt > 1000000:
            eng_cnt = round(eng_cnt / 1000000, 1)
        elif eng_cnt > 1000:
            eng_cnt = round(eng_cnt / 1000, 1)
        cmt_cnt = p.comment_count
        if cmt_cnt > 1000:
            cmt_cnt = round(cmt_cnt / 1000, 1)
        elif cmt_cnt > 1000:
            cmt_cnt = round(cmt_cnt / 1000, 1)
        all_posts.append({
            'platforms': [pl.capitalize() for pl in p.platforms],
            'title': p.title,
            'content': p.description,
            'is_uploaded': p.is_published,
            'is_scheduled': p.is_scheduled,
            'comment_count': cmt_cnt,
            'engagement_count': eng_cnt,
            'tags': p.tags,
            'has_media': p.has_media,
            'cover_image_link': p.media_thumbnail,
            'media': None if not p.has_media else UploadedMedia.objects.filter(post=p).first(),
            'date_uploaded': p.date_uploaded,
            'date_scheduled': p.date_scheduled,
            'media': med,
            'post_id': p.post_id,
            'has_all': len(p.platforms) == 4,
            'has_reddit': 'reddit' in p.platforms,
            'has_tiktok': 'tiktok' in p.platforms,
            'has_facebook': 'facebook' in p.platforms,
            'has_instagram': 'instagram' in p.platforms,
        })

    c_replies = []
    crp = CompanyPostsCommentsReplies.objects.filter(parent_comment_id=comment_id).order_by('-like_count',
                                                                                            '-reply_count', '-pk')
    for cpm in crp:
        replies = []
        crps = CompanyPostsCommentsReplies.objects.filter(parent_comment_id=cpm.comment_id).order_by('-like_count',
                                                                                                     '-reply_count',
                                                                                                     '-pk')
        for c_s in crps:
            replies.append({
                'author': c_s.author,
                'id': c_s.comment_id,
                'author_profile': c_s.author_profile,
                'message_body': c_s.message,
                'isOP': c_s.is_op,
                'like_count': c_s.like_count,
                'reply_count': c_s.reply_count,
                'isPublished': c_s.is_published,
                'date_updated': c_s.date_updated,
            })
        c_replies.append({
            'author': cpm.author,
            'id': cpm.comment_id,
            'author_profile': cpm.author_profile,
            'message_body': cpm.message,
            'isOP': cpm.is_op,
            'like_count': cpm.like_count,
            'reply_count': cpm.reply_count,
            'isPublished': cpm.is_published,
            'date_updated': cpm.date_updated,
            'replies': replies
        })

    context = {
        'success': True,
        'comments_replies': c_replies,
        'comments_data': cmts,
        'posts': all_posts,
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)

    # return Response({'success': 'Bad request'})


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
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


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
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


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
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


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
        tm_bef = (timezone.now() - t_a.date_created).total_seconds()
        ti_bk = ''
        if tm_bef < 86400:
            ti_b = tm_bef // 3600  # how many hours ago
            ti_bk = str(int(ti_b)) + ' hours ago'
            if ti_b < 0:
                ti_b = tm_bef // 60  # how many minutes ago
                ti_bk = str(int(ti_b)) + ' minutes ago'
        t_actv.append(
            {
                'title': t_a.title,
                'time_from': t_a.date_created,
                'date_created': ti_bk,
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
        'chat_messages': chat_messages,
        'team_id': team_id

    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)

@api_view(['POST'])
def deleteTeamFile(request):
    company_id = request.POST.get('company_id', None)
    # team_id = request.POST.get('team_id', None)
    file_id = request.POST.get('file_id', None)
    
    if not all([company_id,file_id]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    memberp=MemberProfile.objects.filter(user=request.user).first()
    if not memberp:
        return Response({'error': 'Unauthorized'})
    cmp=CompanyMember.objects.filter(company=cp,member=memberp).first()
    if not cmp:
        return Response({'error': 'Access Denied'})
    cfile=CompanyTeamFiles.objects.filter(id=file_id).first()
    if not cfile:
        return Response({'error': 'File not available'})
    ct=cfile.team
    if cmp.is_admin or cfile.creator_id == request.user.username:
        who=''
        if cmp.is_admin:
            who='Admin'
        if cfile.creator_id== request.user.username:
            who='Owner'
        ufile=UploadedFiles.objects.filter(team=cfile).first()
        if ufile:
            # remove the associated file
            cact=CompanyTeamActivity(
                    team=ct,
                    title=f'<strong>File</strong>({cfile.file_name}) was <span style="color:red">deleted</span> by <strong>{request.user.username} ({who}) </strong> '
            )
            cact.save()

            file_path = ufile.file.path  # Full file path
            if os.path.exists(file_path):
                os.remove(file_path)  # Remove the file            
            ufile.delete()
        # remove the file pointer
        cfile.delete()
        t_actv = []
        for t_a in CompanyTeamActivity.objects.filter(team=ct).order_by('-pk'):
            tm_bef = (timezone.now() - t_a.date_created).total_seconds()
            ti_bk = ''
            if tm_bef < 86400:
                ti_b = tm_bef // 3600  # how many hours ago
                ti_bk = str(int(ti_b)) + ' hours ago'
                if ti_b < 0:
                    ti_b = tm_bef // 60  # how many minutes ago
                    ti_bk = str(int(ti_b)) + ' minutes ago'
            t_actv.append(
                {
                    'title': t_a.title,
                    'time_from': t_a.date_created,
                    'date_created': ti_bk,
                }
            )
        print(len(t_actv))    
        context = {
            'team_files': CompanyTeamFiles.objects.filter(team=ct).order_by('-pk'),
            'activities':t_actv
        }
        if request.user_agent.is_pc:
            return render(request, 'dashboard.html', context=context)
        else:
            return render(request, 'dashboard_mobile.html', context=context)
    return Response({'error': 'Action denied'})
    
    
@api_view(['POST'])
def uploadTeamFile(request):
    company_id = request.POST.get('company_id', None)
    team_id = request.POST.get('team_id', None)
    file_title = request.POST.get('file_title', None)
    file_notes = request.POST.get('file_notes', None)
    files = request.FILES  # Access uploaded files
    if not all([company_id, files, file_notes, file_title, team_id]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    ct = CompanyTeam.objects.filter(company=cp, id=team_id).first()
    if not ct:
        return Response({'error': 'Bad request'})

    file_doc = []
    for field_name, file in files.items():
        file_doc.append(file)
    mime_type, _ = mimetypes.guess_type(file_doc[0].name)
    if mime_type not in ALLOWED_MIME_TYPES:
        return Response({'error': 'File type not supported.'})
    cact=CompanyTeamActivity(
            team=ct,
            title=f'A <strong>File</strong>({file_title}) was uploaded by <strong>{request.user.username}</strong> '
    )
    cact.save()
    #  save in db 
    ctf = CompanyTeamFiles(
        team=ct,
        creator_id=request.user.username,
        file_name=file_title,
        description=file_notes
    )
    ctf.save()

    upl = UploadedFiles(
        file=file_doc[0],
        team=ctf
    )
    upl.save()
    t_actv = []
    for t_a in CompanyTeamActivity.objects.filter(team=ct).order_by('-pk'):
        tm_bef = (timezone.now() - t_a.date_created).total_seconds()
        ti_bk = ''
        if tm_bef < 86400:
            ti_b = tm_bef // 3600  # how many hours ago
            ti_bk = str(int(ti_b)) + ' hours ago'
            if ti_b < 0:
                ti_b = tm_bef // 60  # how many minutes ago
                ti_bk = str(int(ti_b)) + ' minutes ago'
        t_actv.append(
            {
                'title': t_a.title,
                'time_from': t_a.date_created,
                'date_created': ti_bk,
            }
        )

    context = {
        'team_files': CompanyTeamFiles.objects.filter(team=ct).order_by('-pk'),
        'activities':t_actv

    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


def extract_text_from_pdf(pdf_path):
    with pdfplumber.open(pdf_path) as pdf:
        text = ""
        for page in pdf.pages:
            text += page.extract_text()
    return text


def trainChatbot(cmp):
    cp = CompanyKnowledgeBase.objects.filter(company=cmp).first()
    if not cp:
        print('no data')
    pth = cp.file.path
    v = extract_text_from_pdf(pth)
    print(v)
    pass


# create invite link
@api_view(['POST'])
def uploadTrainDoc(request):
    company_id = request.POST.get('company_id', None)
    erase = request.POST.get('replace_info', None)
    files = request.FILES  # Access uploaded files
    if not all([company_id, files]):
        return Response({'error': 'Bad request'})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Bad request'})
    train_doc = []
    for field_name, file in files.items():
        train_doc.append(file)
        break
    fle = train_doc[0]
    if fle.content_type != "application/pdf":
        return Response({'error': 'Bad request'})

    cpn_doc = CompanyKnowledgeBase.objects.filter(company=cp).first()
    if cpn_doc:
        if cpn_doc.training_inprogress:
            return Response({'error': 'Training in progress. Try again after some time.'})
        if erase == 'true':
            file_path = cpn_doc.file.path  # Full file path
            inv = cpn_doc.file.size
            cfs=CompanyFileSizes.objects.filter(company=cp).first()
            if cfs:
                cfs.size-=inv
                cfs.save()
            delete_file_from_s3(cpn_doc.file.name)
            if os.path.exists(file_path):
                os.remove(file_path)  # Remove the file            
    else:
        cpn_doc = CompanyKnowledgeBase(
            company=cp,
            training_inprogress=True,
            file=file
        )
        cpn_doc.save()
        cfs=CompanyFileSizes.objects.filter(company=cp).first()
        if cfs:
            cfs.size+=file.size
            cfs.save()
        # start thread to train
        tc = threading.Thread(target=trainChatbot, daemon=True, kwargs={'cmp': cp})
        tc.start()

    return Response({'success': 'Bad request'})

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
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


@api_view(['POST'])
def gettiktokCreatorInfo(request):
    company_id = request.POST.get('company_id', None)
    if not all([company_id]):
        return Response({'error': 'Tiktok Bad request '})
    cp = Company.objects.filter(company_id=company_id).first()
    if not cp:
        return Response({'error': 'Tiktok Bad request'})
    ctk = CompanyTiktok.objects.filter(company=cp).first()
    if not ctk:
        return Response({'error': 'TikTok Bad request.Try again or remove TikTok '})
    sess = request.session.get('tiktok_creator_info', {})
    if sess:
        ldta = sess.get('time_updated')
        ldt = datetime.fromisoformat(ldta)
        df = (timezone.now() - ldt).total_seconds()
        dur = sess.get('max_video_post_duration_sec')
        if df < 86400 and dur != None:  # update after 24 hr only
            return Response({
                'max_video_post_duration_sec': sess.get('max_video_post_duration_sec'),
                'stitch_disabled': sess.get('stitch_disabled'),
                'comment_disabled': sess.get('comment_disabled'),
                'duet_disabled': sess.get('duet_disabled')
            })

    try:
        url = "https://open.tiktokapis.com/v2/post/publish/creator_info/query/"
        headers = {
            "Authorization": f"Bearer {ctk.access_token}",
            "Content-Type": "application/json"
        }

        response = requests.post(url, headers=headers)
        res = response.json().get('data')
        print(response.json())
        tk_data = {
            'max_video_post_duration_sec': res.get('max_video_post_duration_sec'),
            'stitch_disabled': res.get('stitch_disabled'),
            'comment_disabled': res.get('comment_disabled'),
            'duet_disabled': res.get('duet_disabled'),
            'time_updated': timezone.now().isoformat()
        }
        request.session['tiktok_creator_info'] = tk_data
        return Response({
            'max_video_post_duration_sec': res.get('max_video_post_duration_sec'),
            'stitch_disabled': res.get('stitch_disabled'),
            'comment_disabled': res.get('comment_disabled'),
            'duet_disabled': res.get('duet_disabled')
        })
    except Exception as e:
        print(traceback.format_exc())
        return Response({'error': 'TikTok Bad request.Try again or remove TikTok '})


def postTiktok(company, description, video, duet, comment, stitch, audience, post_id, mentions):
    """
    Initialize a chunked video upload to TikTok.
    """

    ctk = CompanyTiktok.objects.filter(company=company).first()
    if not ctk:
        return 'No Company Tiktok'
    access_token = ctk.access_token

    vid_ex = '7212243560387726597'
    # vid_ex='7446787420933015558'
    # video_list_url = "https://open.tiktokapis.com/v2/video/list/"
    # params = {
    #     # "video_ids": [vid_ex],
    #     # "fields": "id,title,description,video_url",
    #     "fields": "id,title,video_description,duration,cover_image_url,embed_link"
    # }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # response = requests.post(video_list_url, headers=headers,params=params)
    # # print('')
    # print(response.content)
    # return
    url = "https://open.tiktokapis.com/v2/video/query/"

    params = {
        "fields": "id,views"
    }
    payload = {
        "filters": {
            "video_ids": [
                vid_ex
            ]
        }
    }

    response = requests.post(url, headers=headers, json=payload)

    print(response.json())  # Print the JSON response    
    return

    cpst = CompanyPosts.objects.filter(post_id=post_id).first()
    if not cpst:
        print('failed to retrieve post')
        return
    try:
        ctk = CompanyTiktok.objects.filter(company=company).first()
        if not ctk:
            cpst.has_failed = True
            cpst.save()
            return 'No Company Tiktok'

        access_token = ctk.access_token
        video_size = video['file_size']
        # Get the necessary data from the request
        chunk_size = 20 * 1024 * 1024  # 10 MB in bytes

        # Adjust chunk size if the video is smaller than the chunk size
        if video_size < chunk_size:
            chunk_size = video_size
            total_chunk_count = 1
        if video_size > chunk_size:
            total_chunk_count = 4
            chunk_size = int(video_size / 4)

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
            print("Upload initialized successfully.", response.content)
        else:
            cpst.has_failed = True
            cpst.save()
            print(f"Error: {response.status_code}")
            print(response.json())

            return

        # Parse the response
        upload_data = response.json()
        publish_id = upload_data.get('data', {}).get('publish_id')
        chunk_upload_url = upload_data.get('data', {}).get('upload_url')
        vide_id = publish_id.split('.')[-1]
        print('videeeee', vide_id)

        if not all([publish_id, chunk_upload_url]):
            cpst.has_failed = True
            cpst.save()
            return print({'error': 'Missing publish_id or upload_url in response'})

        with open(video['image_path'], "rb") as video_file:
            video_data = video_file.read()
            total_size = len(video_data)

            upload_headers = {
                "Content-Range": f"bytes 0-{total_size - 1}/{total_size}",
                "Content-Type": "video/mp4"
            }

            upload_response = requests.put(chunk_upload_url, headers=upload_headers, data=video_data)

            if upload_response.status_code == 201:
                print("Video uploaded successfully!", upload_response.content)

            else:
                cpst.has_failed = True
                cpst.save()
                print(f"Failed to upload video: {upload_response.status_code}")
                print(upload_response.json())
                return

            # wait for the video to be published
            published = False
            # Define the API endpoint and access token
            url = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

            # Prepare the payload with the publish ID
            data = {
                "publish_id": publish_id  # Replace with your actual publish ID
            }

            # Send the request
            content_status = "PROCESSING_UPLOAD"
            while content_status == "PROCESSING_UPLOAD":
                response = requests.post(url, headers=headers, json=data, verify=False)
                if response.status_code == 200:
                    status = response.json()
                    content_status = status.get("data", {}).get("status", "Unknown")
                    print('processing status', content_status)
                    if content_status == "PUBLISH_COMPLETE":
                        published = True
                time.sleep(10)

            # get latest updated video
            if published:
                url = "https://open.tiktokapis.com/v2/video/query/"

                params = {
                    "fields": "id,title,video_description,duration,cover_image_url,embed_link"
                }
                payload = {
                    "filters": {
                        "video_ids": [
                            vide_id
                        ]
                    }
                }

                # Print the JSON response    

                # Make the POST request
                count = 0
                while count < 10:  # query the 10 times with each failure
                    response = requests.post(url, headers=headers, json=payload, params=params)

                    print(response.json())
                    # Display the list of videos

                    try:
                        videos = response.json()['videos'][0]
                        print('Found')
                        video_id = videos['id']
                        video_cover = videos['cover_image_url']
                        video_link = videos['embed_link']
                        if not cpst.media_thumbnail:
                            cpst.media_thumbnail = video_cover
                            cpst.save()
                        break
                        # return
                        # time.sleep(10)
                        # count+=1

                    except Exception as e:
                        time.sleep(10)
                        count += 1
                if count >= 10:
                    print('maximum triLa')
                    cpst.has_failed = True
                    cpst.save()
                    return
                # save the tiktok post
                ctkp = CompanyTiktokPosts(
                    post_id=post_id,
                    video_id=video_id,
                    is_published=published,
                    mentions=mentions,
                    cover_image_url=video_cover,
                    post_link=video_link,
                )
                ctkp.save()
                # update the post
                cpst.is_published = True
                cpst.save()
                print('done')
                return print({
                    'message': 'Video uploaded successfully',
                })
            else:
                if cpst.is_published and len(cpst.platforms) > 1:
                    cpst.partial_publish = True
                else:
                    cpst.has_failed = True
                cpst.failure_reasons.append('Uknown error')
                cpst.save()
                ctkp = CompanyTiktokPosts(
                    post_id=post_id,
                    is_published=published,
                )
                ctkp.save()

    except Exception as e:
        if cpst.is_published and len(cpst.platforms) > 1:
            cpst.partial_publish = True
        else:
            cpst.has_failed = True
        cpst.failure_reasons.append(str(e))
        cpst.save()

        return print({'error': 'An unexpected error occurred', 'details': str(e)})


def postInstagram(account_id, media, access_token, description, has_media, post_id, to_stories, to_post, to_reels):
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
    is_carousel = False
    if len(media_urls) > 1:
        is_carousel = True
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
        isImage = True
        if media[0]['content_type'].startswith("video/"):
            isImage = False
        payload = {
            "image_url" if isImage else "video_url": media_urls[0],
            "caption": description,
            "access_token": access_token,
        }
        if not isImage and to_reels:
            payload['media_type'] == 'REELS'
            response = requests.post(url, data=payload)

        if to_stories:
            payload['media_type'] == 'STORIES'
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
    publish_response = requests.post(f"https://graph.facebook.com/v16.0/{account_id}/media_publish",
                                     data=publish_payload)

    if publish_response.status_code == 200:
        post_id = publish_response.json().get("id")
        print(f"post published successfully! Post ID: {post_id}")
    else:
        print(f"Error publishing carousel post: {publish_response.json()}")


def postFacebook(page_id, media, access_token, title, description, is_video, has_media, post_id, to_stories, to_post):
    # API endpoint for creating a post
    url = f"https://graph.facebook.com/v21.0/{page_id}/feed"
    cops = CompanyPosts.objects.filter(post_id=post_id).first()
    if not cops:
        print('Could not get the sending post')
        return

    # save video post
    cfb_pst = CompanyFacebookPosts(
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
        output_image_path = 'thumbnail.jpg'
        if os.path.exists(output_image_path):
            os.remove(output_image_path)
        video_file_path = media[0]['image_path']
        print('extracting from')
        try:
            # Extract the first frame (frame at 0 seconds)
            process = (
                ffmpeg
                .input(video_file_path, ss=0)  # Start at 0 seconds
                .output(output_image_path, vframes=1)
                .run_async(pipe_stdout=True, pipe_stderr=True)
            )
            process.communicate()  # Ensure the process completes
            process.wait()
            print(f"First frame extracted and saved to {output_image_path}")
        except Exception as e:
            print(f"Error extracting frame: {traceback.format_exc()}")
        # Path to the video file
        if to_post:
            # Open the video file and send the POST request
            with open(video_file_path, "rb") as video_file:
                files = {
                    "source": video_file
                }
                response = requests.post(url, data=payload, files=files)

            # Handle the response
            if response.status_code == 200:
                print('the video id A1', response.json().get('id'))

                video_id = response.json().get('id')
                cfb_pst.content_id = video_id
                cfb_pst.is_published = True
                cfb_pst.save()
                cops.is_published = True
                cops.save()
                print("Video uploaded successfully! post")
                if not cops.media_thumbnail:
                    time.sleep(15)
                    url = f"https://graph.facebook.com/v21.0/{video_id}/thumbnails"
                    with open(output_image_path, 'rb') as file:
                        files = {'source': file}
                        params = {'access_token': access_token}
                        response = requests.post(url, files=files, params=params)
                        if response.status_code == 200:
                            print("Thumbnail successfully updated!")
                            print(response.content)

                            url = f"https://graph.facebook.com/v21.0/{video_id}"
                            params = {
                                "fields": "thumbnails",
                                "access_token": access_token
                            }
                            while True:
                                response = requests.get(url, params=params)
                                if response.status_code == 200:
                                    data = response.json()
                                    try:
                                        if data:
                                            thumbnails = data.get("thumbnails", {}).get("data", [])
                                            if thumbnails:
                                                # Get the preferred thumbnail or the first one
                                                cops.media_thumbnail = thumbnails[0].get("uri")
                                                cops.save()
                                            else:
                                                continue
                                        break
                                    # return data['images'][0]['source'] if 'images' in data else None
                                    except:
                                        continue

                                else:
                                    break
                        else:
                            print(f"Failed to set thumbnail: {response.text}")

                    # 

                # get parent host id 
                url = f"https://graph.facebook.com/v21.0/{video_id}"
                params = {
                    "fields": "post",
                    "access_token": access_token
                }
                response = requests.get(url, params=params)
                print('post iddd', response.content)
                if response.status_code == 200:
                    data = response.json()['post']['id']
                    cfb_pst.parent_post_id = data
                    cfb_pst.save()
                    print('save post id', data)

                # delete the media

                if os.path.exists(video_file_path):
                    print('deleting already uploaded video')
                os.remove(output_image_path)
                # default_storage.delete(video_file_path)


            else:
                print(f"Error uploading video: {response.status_code}")
                print(response.json())
        # check if uploading to stories
        elif to_stories:
            print('attempting to upload video to stories')
            # initialise upload 
            url = f"https://graph.facebook.com/v21.0/{page_id}/video_stories"
            payload = {
                "upload_phase": "start",
                "access_token": access_token
            }
            response = requests.post(url, data=payload)
            if response.status_code == 200:
                video_id = response.json().get('video_id')
                upload_url = response.json().get('upload_url')
                print('initialisation successful, ', upload_url)

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
                    "file_size": str(media[0]['file_size']),  # File size in bytes
                }
                files = {
                    "source": video_file
                }

                print('attempting to upload', upload_url)
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
                    p_phse = status_data.get('status').get('processing_phase').get('status')
                    u_phse = status_data.get('status').get('publishing_phase').get('status')
                    cright = status_data.get('status').get('copyright_check_status').get('status')
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
                content_id = response.json().get('id')
                print('the video id B', video_id)

                cfb_pst.content_id = content_id
                cfb_pst.is_published = True
                cfb_pst.save()
                cops.is_published = True
                cops.save()

                print("Video uploaded successfully!")
                # retrieve the images for the display
                if not cops.media_thumbnail:
                    time.sleep(15)
                    url = f"https://graph.facebook.com/v21.0/{video_id}/thumbnails"
                    with open(output_image_path, 'rb') as file:
                        files = {'source': file}
                        params = {'access_token': access_token}
                        response = requests.post(url, files=files, params=params)
                        if response.status_code == 200:
                            print("Thumbnail successfully updated!")
                            print(response.content)

                            url = f"https://graph.facebook.com/v21.0/{video_id}"
                            params = {
                                "fields": "thumbnails",
                                "access_token": access_token
                            }
                            while True:
                                response = requests.get(url, params=params)
                                if response.status_code == 200:
                                    data = response.json()
                                    try:
                                        if data:
                                            thumbnails = data.get("thumbnails", {}).get("data", [])
                                            if thumbnails:
                                                # Get the preferred thumbnail or the first one
                                                cops.media_thumbnail = thumbnails[0].get("uri")
                                                cops.save()
                                            else:
                                                continue
                                        break
                                    # return data['images'][0]['source'] if 'images' in data else None
                                    except:
                                        continue

                                else:
                                    break
                        else:
                            print(f"Failed to set thumbnail: {response.text}")

                # delete the media
                if os.path.exists(video_file_path):
                    print('deleting already uploaded video')
                os.remove(output_image_path)

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
                response = requests.post(url, json=payload)

                if response.status_code == 200:
                    content_id = response.json().get('id')
                    cfb_pst.content_id = content_id
                    cfb_pst.is_published = True
                    cfb_pst.save()
                    cops.is_published = True
                    cops.save()

                    print("Post created successfully with multiple photos!")

                    # retrieve the images for the display
                    if not cops.media_thumbnail:
                        print('gettong thumbnail')
                        url = f"https://graph.facebook.com/v21.0/{photo_ids[0]['media_fbid']}"
                        params = {
                            "fields": "images",
                            "access_token": access_token
                        }

                        response = requests.get(url, params=params)
                        if response.status_code == 200:
                            data = response.json()
                            # Get the highest-resolution image URL
                            if data:
                                cops.media_thumbnail = data['images'][0]['source']
                                cops.save()
                            # return data['images'][0]['source'] if 'images' in data else None

                else:
                    print(f"Error creating post: {response.status_code}")
                    print(response.json())

            # check if user is uploading to stories
            elif to_stories:
                print('attempting to upload photo(s) to stories')
                for ph_id in photo_ids:
                    url = f"https://graph.facebook.com/v21.0/{page_id}/photo_stories"
                    payload = {
                        "photo_id": ph_id['media_fbid'],
                        "access_token": access_token
                    }
                    # Make the POST request to create the post
                    response = requests.post(url, json=payload)

                if response.status_code == 200:
                    content_id = response.json().get('id')
                    cfb_pst.content_id = content_id
                    cfb_pst.is_published = True
                    cops.is_published = True
                    cops.save()

                    cfb_pst.save()
                    print("stories created successfully with multiple photos!")
                    # retrieve the images for the display
                    if not cops.media_thumbnail:
                        time.sleep(15)
                        url = f"https://graph.facebook.com/v21.0/{video_id}/thumbnails"
                        with open(output_image_path, 'rb') as file:
                            files = {'source': file}
                            params = {'access_token': access_token}
                            response = requests.post(url, files=files, params=params)
                            if response.status_code == 200:
                                print("Thumbnail successfully updated!")
                                print(response.content)

                                url = f"https://graph.facebook.com/v21.0/{video_id}"
                                params = {
                                    "fields": "thumbnails",
                                    "access_token": access_token
                                }
                                while True:
                                    response = requests.get(url, params=params)
                                    if response.status_code == 200:
                                        data = response.json()
                                        try:
                                            if data:
                                                thumbnails = data.get("thumbnails", {}).get("data", [])
                                                if thumbnails:
                                                    # Get the preferred thumbnail or the first one
                                                    cops.media_thumbnail = thumbnails[0].get("uri")
                                                    cops.save()
                                                else:
                                                    continue
                                            break
                                        # return data['images'][0]['source'] if 'images' in data else None
                                        except:
                                            continue

                                    else:
                                        break
                            else:
                                print(f"Failed to set thumbnail: {response.text}")

                    # delete the media
                    if os.path.exists(video_file_path):
                        print('deleting already uploaded video')
                    os.remove(output_image_path)
                else:
                    print(f"Error creating post: {response.status_code}")
                    print(response.json())
        else:
            print("No photos were successfully uploaded.")
    else:
        if to_post:
            try:
                url = f"https://graph.facebook.com/v21.0/{page_id}/feed"

                payload = {
                    "message": description,
                    "access_token": access_token,
                }

                response = requests.post(url, data=payload)

                if response.status_code == 200:
                    print("Link post created successfully!")
                    print(response.json())
                    print()
                    content_id = response.json().get('id')
                    cfb_pst.content_id = content_id
                    cfb_pst.is_published = True
                    cfb_pst.save()
                    cops.is_published = True
                    cops.save()
                    cops.is_published = True
                    cops.save()

                    print(response.json())
                else:
                    if not cops.partial_publish:
                        cops.has_failed = True
                        cops.failure_reasons.append('Failed to post to facebook')
                        cops.save()
                    print(f"Error creating post: {response.status_code}")
                    print(response.json())
            except:
                if not cops.partial_publish:
                    cops.has_failed = True
                    cops.failure_reasons.append('Failed to post to facebook')


def postReddit(title, description, subs, hasMedia, files, nsfw_tag, spoiler_tag, red_refresh_token, post_id, company):
    cr = CompanyReddit.objects.filter(company=company).first()
    pst = CompanyPosts.objects.filter(post_id=post_id).first()
    if not pst:
        return
    try:
        reddit = praw.Reddit(
            client_id=settings.REDDIT_CLIENT_ID,
            client_secret=settings.REDDIT_CLIENT_SECRET,
            user_agent=settings.REDDIT_USER_AGENT,
            refresh_token=red_refresh_token,
        )
        sub_tr = []
        published = False
        failed_publish = False
        fail_reasons = []
        for s in subs:
            for cs in cr.subs:
                sb = s.split('r/')[-1]
                default_flair = ''
                if sb == cs['sub']:
                    for fl in cs['flairs']:
                        if fl['selected']:
                            default_flair = fl['id']
                            break
                    # upload the post
                    subreddit = reddit.subreddit(sb)
                    if hasMedia:
                        # upload with media
                        if len(files) == 1:
                            # check if image or video and upload accoordingly
                            f = files[0]['image_path']
                            content_type = files[0]['content_type']
                            if content_type.startswith("image/"):
                                # check image posting
                                if subreddit.allow_images:
                                    print('submitting image')
                                    try:
                                        submission = subreddit.submit_image(
                                            title=description,
                                            image_path=f,
                                            flair_id=default_flair,
                                            timeout=30,
                                            nsfw=nsfw_tag,
                                            spoiler=spoiler_tag

                                        )
                                        published = True
                                        if not pst.media_thumbnail:
                                            pst.media_thumbnail = submission.url

                                        sub_tr.append({
                                            'sub_name': sb,
                                            'id': submission.id,
                                            'link': submission.url,
                                            'permalink': f"https://www.reddit.com{submission.permalink}",
                                            'published': True,
                                            'failed': False,
                                            'result': 'Submission was successful',
                                            'upvotes': 0,
                                            'comments': 0,
                                            'upvote_ratio': 0,
                                            'crossposts': 0
                                        })
                                        # default_storage.delete(files[0]['image_path'])
                                        
                                    except Exception as e:
                                        failed_publish = True
                                        print('failed to submit to reddit', str(traceback.format_exc()))
                                        fail_reasons.append(f'Submission to r/{sb} Failed')
                                        sub_tr.append({
                                            'sub_name': sb,
                                            'id': '',
                                            'link': '',
                                            'published': False,
                                            'failed': True,
                                            'result': 'Uknown reason. Contact sub MODs ',
                                            'comments': 0,
                                            'upvotes': 0,
                                            'upvote_ratio': 0,
                                            'crossposts': 0
                                        })
                                else:
                                    failed_publish = True
                                    fail_reasons.append(f'Submission to r/{sb} Failed')
                                    sub_tr.append({
                                        'sub_name': sb,
                                        'id': '',
                                        'link': '',
                                        'published': False,
                                        'failed': True,
                                        'result': f'r/{sb} does not allow image sharing.',
                                        'comments': 0,
                                        'upvotes': 0,
                                        'upvote_ratio': 0,
                                        'crossposts': 0
                                    })
                                # cr.save()

                            elif content_type.startswith("video/"):
                                print('submitting video')
                                if subreddit.allow_videos:
                                    try:
                                        submission = subreddit.submit_video(
                                            title=title,
                                            video_path=f,
                                            timeout=30,
                                            nsfw=nsfw_tag,
                                            spoiler=spoiler_tag

                                        )
                                        published = True
                                        print(f"Video post created successfully: {submission.url}")
                                        if not pst.media_thumbnail:
                                            pst.media_thumbnail = submission.url

                                        sub_tr.append({
                                            'sub_name': sb,
                                            'id': submission.id,
                                            'link': submission.url,
                                            'permalink': f"https://www.reddit.com{submission.permalink}",
                                            'published': True,
                                            'failed': False,
                                            'result': 'Submission was accepted',
                                            'comments': 0,
                                            'upvotes': 0,
                                            'upvote_ratio': 0,
                                            'crossposts': 0
                                        })
                                        default_storage.delete(files[0]['image_path'])
                                    except Exception as e:
                                        failed_publish = True
                                        fail_reasons.append(f'Submission to r/{sb} Failed')
                                        sub_tr.append({
                                            'sub_name': sb,
                                            'id': '',
                                            'link': '',
                                            'published': False,
                                            'failed': True,
                                            'result': 'Uknown reason. Contact sub MODs ',
                                            'comments': 0,
                                            'upvotes': 0,
                                            'upvote_ratio': 0,
                                            'crossposts': 0
                                        })
                                else:
                                    failed_publish = True
                                    fail_reasons.append(f'Submission to r/{sb} Failed')
                                    sub_tr.append({
                                        'sub_name': sb,
                                        'id': '',
                                        'link': '',
                                        'published': False,
                                        'failed': True,
                                        'result': f'r/{sb} does not allow video sharing.',
                                        'comments': 0,
                                        'upvotes': 0,
                                        'upvote_ratio': 0,
                                        'crossposts': 0
                                    })
                                # cr.save()

                            else:
                                failed_publish = True
                                fail_reasons.append(f'Submission to r/{sb} Failed')
                                sub_tr.append({
                                    'sub_name': sb,
                                    'id': '',
                                    'link': '',
                                    'published': False,
                                    'failed': True,
                                    'result': f'Unsupported media type {content_type}',
                                    'comments': 0,
                                    'upvotes': 0,
                                    'upvote_ratio': 0,
                                    'crossposts': 0
                                })
                                # cr.save()
                                # default_storage.delete(files[0]['image_path'])
                        else:
                            # # Submit a gallery post
                            if subreddit.allow_images:
                                try:
                                    submission = subreddit.submit_gallery(
                                        title=description,
                                        images=files,
                                        flair_id=default_flair,
                                        nsfw=nsfw_tag,
                                        spoiler=spoiler_tag
                                    )
                                    published = True

                                    # Get media metadata
                                    gallery_data = submission.media_metadata
                                    cover_image_url = ''
                                    if gallery_data:
                                        # Find the cover image
                                        cover_image_id = submission.gallery_data['items'][0]['media_id']
                                        print(len(gallery_data[cover_image_id]['p']))
                                        cover_image_url = gallery_data[cover_image_id]['p'][-1][
                                            'u']  # Get the first preview
                                        # Reddit URLs may contain encoded characters like "&amp;", decode them
                                        cover_image_url = cover_image_url.replace("&amp;", "&")
                                    # clear the respective temporary files
                                    if not pst.media_thumbnail:
                                        pst.media_thumbnail = cover_image_url

                                    sub_tr.append({
                                        'sub_name': sb,
                                        'id': submission.id,
                                        'link': cover_image_url,
                                        'permalink': f"https://www.reddit.com{submission.permalink}",
                                        'published': True,
                                        'failed': False,

                                        'result': 'Submission was successful',
                                        'comments': 0,
                                        'upvotes': 0,
                                        'upvote_ratio': 0,
                                        'crossposts': 0
                                    })
                                    for f in files:
                                        default_storage.delete(f['image_path'])
                                except Exception as e:
                                    print(traceback.format_exc())
                                    failed_publish = True
                                    fail_reasons.append(f'Submission to r/{sb} Failed')
                                    sub_tr.append({
                                        'sub_name': sb,
                                        'id': '',
                                        'link': '',
                                        'published': False,
                                        'failed': True,
                                        'result': 'Uknown reason. Contact sub MODs ',
                                        'comments': 0,
                                        'upvotes': 0,
                                        'upvote_ratio': 0,
                                        'crossposts': 0
                                    })
                            else:
                                failed_publish = True
                                fail_reasons.append(f'Submission to r/{sb} Failed')
                                sub_tr.append({
                                    'sub_name': sb,
                                    'id': '',
                                    'link': '',
                                    'published': False,
                                    'failed': True,
                                    'result': f'r/{sb} does not allow image sharing.',
                                    'comments': 0,
                                    'upvotes': 0,
                                    'upvote_ratio': 0,
                                    'crossposts': 0
                                })
                            # cr.save()

                    else:
                        if subreddit.submission_type == 'any' or subreddit.submission_type == 'self':
                            submission = subreddit.submit(
                                title,
                                selftext=description,
                                flair_id=default_flair,
                                nsfw=nsfw_tag,
                                spoiler=spoiler_tag)
                            published = True
                            sub_tr.append({
                                'sub_name': sb,
                                'id': submission.id,
                                'link': submission.url,
                                'permalink': f"https://www.reddit.com{submission.permalink}",
                                'published': True,
                                'failed': False,
                                'result': 'Submission was successful',
                                'comments': 0,
                                'upvotes': 0,
                                'upvote': 0,
                                'upvote_ratio': 0,
                                'crossposts': 0
                            })
                        else:
                            failed_publish = True
                            fail_reasons.append(f'Submission to r/{sb} Failed')
                            sub_tr.append({
                                'sub_name': sb,
                                'id': '',
                                'link': '',
                                'published': False,
                                'failed': True,
                                'result': f'r/{sb} does not allow text submissions.',
                                'comments': 0,
                                'upvotes': 0,
                                'upvote_ratio': 0,
                                'crossposts': 0
                            })
                        # cr.save()
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

        if failed_publish and published:
            pst.is_published = True
            pst.partial_publish = True
            for res in fail_reasons:
                pst.failure_reasons.append(res)
            pst.save()
        elif not failed_publish and published:
            pst.is_published = True
            pst.save()
        elif failed_publish and not published:
            if not pst.is_published:
                pst.has_failed = True
            pst.failure_reasons.extend(fail_reasons)
            pst.save()
        
    except:
        pst.is_published=False
        pst.has_failed=True
        pst.save()
        return


@api_view(['POST'])
def deletePostComment(request):
    post_id = request.POST.get('post_id', None)
    comment_id = request.POST.get('comment_id', None)
    action_type = request.POST.get('action_type', None)
    if not all([post_id, action_type]):
        return Response({'error': 'Bad request'})
    cpst = CompanyPosts.objects.filter(post_id=post_id).first()
    if not cpst:
        return Response({'error': 'Post unavailable or already deleted'})

    pltfrms = cpst.platforms
    
    # check if already uploaded
    for platform in pltfrms:
        if 'reddit' in platform.lower():
            # deleting reddit post /comment
            print('isreddit')
            cr = CompanyReddit.objects.filter(company=cpst.company).first()
            if not cr:
                continue
            reddit = praw.Reddit(
                client_id=settings.REDDIT_CLIENT_ID,
                client_secret=settings.REDDIT_CLIENT_SECRET,
                user_agent=settings.REDDIT_USER_AGENT,
                refresh_token=cr.refresh_token,
            )
            if action_type == 'post':
                print('deleting post',post_id)
                crp = CompanyRedditPosts.objects.filter(post_id=post_id).first()
                if crp:
                    if cpst.is_published:
                        sbs = crp.subs
                        for sb in sbs:
                            try:
                                sb_id = sb['id']
                                submission = reddit.submission(id=sb_id)
                                submission.delete()
                                print('deleted from ', sb['sub_name'])
                            except:
                                print('unable to delete')
                                print(traceback.format_exc())
                                continue
                    crp.delete()
                else:
                    print('No post')  
                    
        if 'facebook' in platform.lower():
            cfbp = CompanyFacebook.objects.filter(company=cpst.company).first()
            if not cfbp:
                continue
            if action_type == 'post':
                cfp = CompanyFacebookPosts.objects.filter(post_id=post_id).first()
                if cfp:
                    if cpst.is_published:
                        if cfp.content_id:
                            url = f"https://graph.facebook.com/v21.0//{cfp.content_id}"
                            payload = {
                                "access_token": cfbp.page_access_token,
                            }
                            response = requests.delete(url, data=payload)
                            if response.status_code == 200:
                                print("Post deleted successfully:", response.json())
                                cfp.delete()
                            else:
                                print("Error deleting post:", response.json())
                            

    # delete uploaded media from s3 if present
    if action_type == 'post':
        upm=UploadedMedia.objects.filter(post=cpst)
        for up in upm:
            # free up spaces
            
            delete_file_from_s3(file_key=up.media.name)
        cpst.delete()

    cp = CompanyPosts.objects.filter(company=cpst.company).order_by('-pk')
    all_posts = []
    if not cp:
        for p in cp:
            um = UploadedMedia.objects.filter(post=p)
            med = []
            for m in um:
                med.append({
                    'media_url': m.media.url,
                    'is_video': False
                })
            reds = []
            cover_image_link = ''

            if 'reddit' in p.platforms:
                cr = CompanyRedditPosts.objects.filter(post_id=p.post_id)
                if cr:
                    for c in cr:
                        t_en = 0
                        t_com = 0
                        for k in c.subs:
                            if k['published']:
                                p_id = k['id']
                                submission = reddit.submission(id=p_id)
                                k['upvote_ratio'] = submission.upvote_ratio * 100
                                k['upvotes'] = submission.score
                                k['comments'] = submission.num_comments
                                k['crossposts'] = submission.num_crossposts
                                reds.append(k)

                                vlx = submission.score + submission.num_comments + submission.num_crossposts
                                t_en += vlx
                                t_com += submission.num_comments
                        p.comment_count = t_com
                        p.engagement_count = t_en
                        p.save()
                        c.save()

            eng_cnt = p.engagement_count
            if eng_cnt > 1000000:
                eng_cnt = round(eng_cnt / 1000000, 1)
            elif eng_cnt > 1000:
                eng_cnt = round(eng_cnt / 1000, 1)
            cmt_cnt = p.comment_count
            if cmt_cnt > 1000:
                cmt_cnt = round(cmt_cnt / 1000, 1)
            elif cmt_cnt > 1000:
                cmt_cnt = round(cmt_cnt / 1000, 1)
            all_posts.append({
                'platforms': [pl.capitalize() for pl in p.platforms],
                'title': p.title,
                'content': p.description,
                'is_uploaded': p.is_published,
                'is_scheduled': p.is_scheduled,
                'comment_count': cmt_cnt,
                'engagement_count': eng_cnt,
                'tags': p.tags,
                'has_media': p.has_media,
                'cover_image_link': p.media_thumbnail,
                'media': None if not p.has_media else UploadedMedia.objects.filter(post=p).first(),
                'date_uploaded': p.date_uploaded,
                'date_scheduled': p.date_scheduled,
                'media': med,
                'post_id': p.post_id,
                'has_all': len(p.platforms) == 4,
                'has_reddit': 'reddit' in p.platforms,
                'has_tiktok': 'tiktok' in p.platforms,
                'has_facebook': 'facebook' in p.platforms,
                'has_instagram': 'instagram' in p.platforms,

            })
    else:
        for p in cp:
            um = UploadedMedia.objects.filter(post=p)
            med = []
            for m in um:
                med.append({
                    'media_url': m.media.url,
                    'is_video': False
                })
            reds = []
            cover_image_link = ''

            if 'reddit' in p.platforms:
                cr = CompanyRedditPosts.objects.filter(post_id=p.post_id).first()

            eng_cnt = p.engagement_count
            if eng_cnt > 1000000:
                eng_cnt = round(eng_cnt / 1000000, 1)
            elif eng_cnt > 1000:
                eng_cnt = round(eng_cnt / 1000, 1)
            cmt_cnt = p.comment_count
            if cmt_cnt > 1000:
                cmt_cnt = round(cmt_cnt / 1000, 1)
            elif cmt_cnt > 1000:
                cmt_cnt = round(cmt_cnt / 1000, 1)
            all_posts.append({
                'platforms': [pl.capitalize() for pl in p.platforms],
                'title': p.title,
                'content': p.description,
                'is_uploaded': p.is_published,
                'is_scheduled': p.is_scheduled,
                'is_published': p.is_published,
                'has_failed': p.has_failed,
                'comment_count': cmt_cnt,
                'engagement_count': eng_cnt,
                'tags': p.tags,
                'has_media': p.has_media,
                'cover_image_link': p.media_thumbnail,
                'media': None if not p.has_media else UploadedMedia.objects.filter(post=p).first(),
                'date_uploaded': p.date_uploaded,
                'date_scheduled': p.date_scheduled,
                'media': med,
                'post_id': p.post_id,
                'has_all': len(p.platforms) == 4,
                'has_reddit': 'reddit' in p.platforms,
                'has_tiktok': 'tiktok' in p.platforms,
                'has_facebook': 'facebook' in p.platforms,
                'has_instagram': 'instagram' in p.platforms,

            })
        # upd_pst=threading.Thread(target=updatePosts,daemon=True, kwargs={
        #         'company_id':company_id,
        #     })
        # upd_pst.start()

    context = {
        'posts': all_posts,
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)

@api_view(['POST'])
def requestFeature(request):
    company_id = request.POST.get('company_id', None)
    title = request.POST.get('title', None)
    description = request.POST.get('details', None)
    cp = Company.objects.filter(company_id=company_id).first()
    
    # check subscription
    if not any([cp, title,description]):
        return Response({'error': 'Bad request'})
    cfr=CompanyFeatureRequest(
        company=cp,
        title=title,
        details=description
    )
    cfr.save()
    context = {
        'freqs': CompanyFeatureRequest.objects.filter(company=cp).order_by('-pk')
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)

    
    
    
@api_view(['POST'])
def uploadPost(request):
    company_id = request.POST.get('company_id', None)
    title = request.POST.get('title', None)
    description = request.POST.get('description', None)
    timezonet = request.POST.get('timezone', None)

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
    tk_tiktok_mentions = request.POST.get('tk_tiktok_mentions', None)

    tk_audience = 'PUBLIC_TO_EVERYONE'
    if tk_to_friends:
        tk_audience = 'MUTUAL_FOLLOW_FRIENDS'
    elif tk_to_only_me:
        tk_audience = 'SELF_ONLY'
    tk_description = f'{description} {hashTags} {tk_tiktok_mentions}'

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

    fb_descr = f'{description} {hashTags} '
    # Reddit
    red_is_nsfw = request.POST.get('red_is_nsfw', 'false').lower() == 'true'
    red_is_spoiler = request.POST.get('red_is_spoiler', 'false').lower() == 'true'
    target_subs = request.POST.get('red_sub_selected', None)

    date_scheduled = request.POST.get('date_scheduled', None)

    if not all([company_id, description]):
        return Response({'error': 'Bad request'})

    tsbs = target_subs.split(',')
    cp = Company.objects.filter(company_id=company_id).first()
    
        # check subscription
    if not any([cp.company_free_trial, cp.company_active_subscription]):
        return Response({'error': 'Kindly renew your subscription to continue.'})

    files = request.FILES  # Access uploaded files
    gallery_items = []
    for field_name, file in files.items():
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            for chunk in file.chunks():
                temp_file.write(chunk)
            
            temp_file_path = temp_file.name  # Absolute path to the temp file
            
        # Add details to gallery_items
        gallery_items.append({
            "image_path": temp_file_path,  # Local path to the file
            "content_type": file.content_type,
            "file_size": file.size,
        })        
    utc_datetime = timezone.now()

    if isScheduled:
        time_format = "%A, %d %B %Y %I:%M %p"
        # Convert to datetime object
        datetime_object = datetime.strptime(date_scheduled, time_format)
        
         # Define the timezone (Africa/Nairobi in this case)
        local_timezone = pytz.timezone(timezonet)

        # Localize the datetime object to the specified timezone
        localized_datetime = local_timezone.localize(datetime_object)

        # Convert the localized datetime to UTC
        utc_datetime = localized_datetime.astimezone(pytz.utc)

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
    is_video = False
    if len(gallery_items) > 0:
        glctyp = gallery_items[0]['content_type']
        if glctyp.startswith("video/"):
            is_video = True

    cpst = CompanyPosts(
        company=cp,
        post_id=post_id,
        platforms=platform,
        title=title,
        description=description,
        is_scheduled=isScheduled,
        has_media=hasMedia,
        is_video=is_video,
        date_scheduled=utc_datetime
    )
    ht = hashTags.split()
    cpst.tags.extend(ht)
    cpst.save()

    if not isScheduled:
        # post to the respective platforms
        if redditSelected:
            cr = CompanyReddit.objects.filter(company=cp).first()
            redThread = threading.Thread(target=postReddit, daemon=True, kwargs={
                'title': title,
                'description': description,
                'subs': tsbs,
                'hasMedia': hasMedia,
                'files': gallery_items,
                'nsfw_tag': red_is_nsfw,
                'spoiler_tag': red_is_spoiler,
                'red_refresh_token': cr.refresh_token,
                'post_id': post_id,
                'company': cp

            })
            redThread.start()
        if tiktokSelected:
            glctyp = gallery_items[0]['content_type']
            if not glctyp.startswith("video/"):
                return 'Non video'
            tkThread = threading.Thread(target=postTiktok, daemon=True, kwargs={
                'company': cp,
                'description': tk_description,
                'video': gallery_items[0],
                'duet': tk_allow_duet,
                'comment': tk_allow_comment,
                'stitch': tk_allow_stitch,
                'audience': tk_audience,
                'post_id': post_id,
                'mentions': tk_tiktok_mentions
            })
            tkThread.start()
        if facebookSelected:
            cfb = CompanyFacebook.objects.filter(company=cp).first()
            if not cfb:
                return
            isVideo = False
            if hasMedia:
                glctyp = gallery_items[0]['content_type']
                if glctyp.startswith("video/"):
                    isVideo = True
            fbThread = threading.Thread(target=postFacebook, daemon=True, kwargs={
                'media': gallery_items,
                'page_id': cfb.page_id,
                'post_id': post_id,
                'access_token': cfb.page_access_token,
                'is_video': isVideo,
                'description': description,
                'has_media': hasMedia,
                'title': title,
                'to_stories': to_fb_stories,
                'to_post': to_fb_posts

            })
            fbThread.start()
        if instagramSelected:
            cig = CompanyInstagram.objects.filter(company=cp).first()
            igThread = threading.Thread(target=postInstagram, daemon=True, kwargs={
                'account_id': cig.account_id,
                'media': gallery_items,
                'access_token': cig.long_lived_token,
                'description': description,
                'has_media': hasMedia,
                'post_id': post_id,
                'to_stories': to_ig_stories,
                'to_post': to_ig_posts,
                'to_reels': to_ig_reels
            })
            igThread.start()
    else:
        # delete temporarily stored files
        for f in gallery_items:
            # use threads
            delThread=threading.Thread(target=delete_temp_files,kwargs={'file_path':f['image_path']},daemon=True)
            delThread.start()
        # scheduled
        if hasMedia:
            f_size=0
            fles=[]
            for field_name, file in files.items():
                fles.append(file)
            for file in fles:
                up=UploadedMedia(
                    post=cpst,
                    media=file
                )
                up.save()
                f_size+=file.size
            cfs=CompanyFileSizes.objects.filter(company=cp).first()
            if not cfs:
                alct=0
                if cp.company_free_trial:
                    alct=524288000
                elif cp.company_subscription_tier == 1:
                    alct=1073741824
                elif cp.company_subscription_tier == 2:
                    alct=10737418240
                elif cp.company_subscription_tier == 3:
                    alct=107374182400
                    
                cfs = CompanyFileSizes(
                        company=cp,
                        size=f_size,
                        allocated=alct
                        )
                cfs.save()
            else:
                cfs.size+=f_size
                cfs.save()
            
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
        if redditSelected:
            cred = CompanyRedditPosts(
                post_id=post_id,
                nsfw_tag=red_is_nsfw,
                spoiler_flag=red_is_spoiler,
                target_subs=tsbs)
            cred.save()
        if facebookSelected:
            cfb_pst = CompanyFacebookPosts(
                post_id=post_id,
                to_stories=to_fb_stories,
                to_posts=to_fb_posts)
            cfb_pst.save()

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
        file_size = image.size
        if file_size>5000000:
            return Response({'error': 'File exceeds size limit of 5MB'})
        inv=0
        cpp = CompanyProfilePicture.objects.filter(company=cm).first()
        
        if cpp:
            inv=cpp.p_pic.size 
            delete_file_from_s3(file_key=cpp.p_pic.name)
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
        f"&scope=read_insights,business_management,instagram_basic,instagram_manage_comments,instagram_manage_insights,instagram_content_publish,instagram_manage_messages,pages_read_engagement,pages_manage_engagement,pages_manage_metadata"
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
        f"&scope=pages_show_list,pages_manage_posts,pages_read_engagement,pages_manage_engagement,business_management,pages_manage_metadata,pages_messaging,pages_read_user_content,read_insights,instagram_manage_messages,pages_manage_metadata,instagram_basic"
        f"&state={state}"
    )
    return oauth_url


# @api_view(['GET'])
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


def get_instagram_account_insights(access_token, instagram_account_id, **kwargs):
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
    cp_id = kwargs.get('company_id', None)
    if cp_id:
        cp = Company.objects.filter(company_id=cp_id).first()
        if cp:
            cig = CompanyInstagram.objects.filter(company=cp).first()
            if cig:
                tnw = timezone.now()
                tdiff = tnw - cig.last_update_time
                if tdiff.total_seconds() > 86400:
                    # cig.followers_trend=[]
                    # cig.impressions=[]
                    # cig.reach=[]
                    cig.last_update_time = timezone.now()
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
    # print(profile_info)

    url2 = f"https://graph.facebook.com/v21.0/{page_id}/insights"
    params2 = {
        "metric": "page_impressions,page_fans,page_views_total",
        "access_token": access_token,
        'period': 'day'
    }

    response = requests.get(url2, params=params2)

    page_insights = response.json()
    # print(response.json())
    page_impress = 0
    page_fans = 0
    page_vws = 0
    if page_insights:
        for pg in page_insights.get('data'):
            pim = pg.get('name')
            if pim == 'page_impressions':
                prd = pg.get('period')
                vll = pg.get('values')[-1].get('value')
                page_impress = vll

            if pim == 'page_views_total':
                vll = pg.get('values')[-1].get('value')
                page_vws = vll

            if pim == 'page_fans':
                vll = pg.get('values')[-1].get('value')
                page_fans = vll

    # print(page_insights.get('data').get('page_fans'))
    vl_id = kwargs.get('company_id', None)
    if vl_id:
        cp = Company.objects.filter(company_id=vl_id).first()
        if cp:
            cmf = CompanyFacebook.objects.filter(company=cp).first()

            if cmf:
                tnw = timezone.now()
                tdiff = tnw - cmf.last_update_time
                if tdiff.total_seconds() > 86400:
                    # cmf.page_fans=[]
                    # cmf.page_views_total=[]
                    # cmf.impressions=[]

                    cmf.page_fans.append(page_fans)
                    cmf.page_views_total.append(page_vws)
                    cmf.impressions.append(page_impress)
                    cmf.last_update_time = timezone.now()
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
    insgts = get_facebook_page_insights(page_access_token, pg_id)

    if cf:
        cf.short_lived_token = access_token
        cf.account_id = pg_id
        cf.long_lived_token = l_lived_token
        cf.linked = True
        cf.active = True
        cf.page_access_token = page_access_token
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


def getRedditSubInfo(subs, reddit):
    print('getting subs analytics ', subs)
    for sub in subs:
        crs = CompanyRedditSubs.objects.filter(sub_name=sub).first()
        if crs:
            # check the last time it was updated
            lst_upd = crs.last_updated
            dfr = (timezone.now() - lst_upd).total_seconds()
            if dfr > 3600:  # updated more than 1hr ago
                sr = reddit.subreddit(sub)
                crs.full_name = sr.name
                crs.description = sr.description
                crs.subscriber_count = sr.subscribers
                crs.user_is_banned = sr.user_is_banned
                pr = sr.rules()
                rules = pr['rules']
                rls = []
                for r in rules:
                    rls.append(
                        {'rule': r['short_name'], 'description': r['description']}
                    )
                crs.sub_rules = rls
                crs.last_updated - timezone.now()
                crs.save()
        else:
            sr = reddit.subreddit(sub)
            pr = sr.rules()
            rules = pr['rules']
            rls = []
            for r in rules:
                rls.append(
                    {'rule': r['short_name'], 'description': r['description']}
                )

            crs = CompanyRedditSubs(
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
    dt = []
    for sub in subs:
        crs = CompanyRedditSubs.objects.filter(sub_name=sub).first()
        if crs:
            dt.append({
                'name': crs.sub_name,
                'description': crs.description,
                'subscribers': crs.subscriber_count,
                'isBanned': crs.user_is_banned,
                'rules': crs.sub_rules
            })
        else:
            sr = reddit.subreddit(sub)
            pr = sr.rules()
            rules = pr['rules']
            rls = []
            for r in rules:
                rls.append(
                    {'rule': r['short_name'], 'description': r['description']}
                )

            crs = CompanyRedditSubs(
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
                'rules': crs.sub_rules
            })
    context = {
        'sub_info': dt,
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


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
        sub_analyt_thrd = threading.Thread(target=getRedditSubInfo, daemon=True,
                                           kwargs={'subs': subs, 'reddit': reddit})
        sub_analyt_thrd.start()

        # check if we have the flairs already
        for subreddit_name in subs:
            present = False
            for sr in cr.subs:
                if sr['sub'] == subreddit_name:
                    present = True
                    rt.append({'sub_r': subreddit_name,
                               'optional': sr['flair_optional'],
                               'flairs_r': sr['flairs']})
            if not present:
                vl = []
                try:
                    subreddit = reddit.subreddit(subreddit_name)
                    flair_options = list(subreddit.flair.link_templates)
                    optional = False

                    for f in flair_options:
                        if not f['mod_only']:
                            vl.append({
                                'name': f['text'],
                                'id': f['id'],
                                'selected': False
                            })
                except:
                    optional = True
                rt.append({
                    'sub_r': subreddit_name,
                    'optional': optional,
                    'flairs_r': vl})

    context = {
        'flair_results': rt,
    }
    if request.user_agent.is_pc:
        return render(request, 'dashboard.html', context=context)
    else:
        return render(request, 'dashboard_mobile.html', context=context)


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
    init_sub = []
    if cr:
        init_sub = cr.subs
        for flr in json.loads(flairs):
            for sr in init_sub:
                if flr['name'] == sr['sub']:
                    for f_id in sr['flairs']:
                        try:
                            if f_id['id'] == flr['id']:
                                f_id['selected'] = True
                                pass
                            else:
                                f_id['selected'] = False
                            modified = True  # Mark as modified
                        except:
                            return Response({'success': 'Updated successfully'})
    if modified:
        cr.subs = init_sub
        cr.save()
    return Response({'success': 'Updated successfully'})


def reddit_auth_link(company_id):
    state = urllib.parse.quote_plus(str(company_id))  # Ensure URL encoding for special characters
    authorization_url = reddit.auth.url(
        ['identity', 'submit', 'read', 'mysubreddits', 'flair', "history", 'modposts', 'vote', 'edit',
         'privatemessages'], state=state,
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
