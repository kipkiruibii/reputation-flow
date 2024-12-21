from django.core.management.base import BaseCommand
import time
import os
import sys
import django 
import threading
import requests
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reputation_fow.settings')
django.setup()
# Get the current directory of the script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Move up three directories
parent_dir = os.path.abspath(os.path.join(current_dir, '../../..'))

# Add the parent directory to sys.path
sys.path.append(parent_dir)

from reputation_app.models import *
from django.conf import settings


def exchangeFacebookToken(companyfacebook,access_token):
    exchange_url = f"https://graph.facebook.com/v21.0/oauth/access_token"
    params = {
        "grant_type": "fb_exchange_token",
        "client_id": settings.FACEBOOK_APP_ID,
        "client_secret": settings.FACEBOOK_APP_SECRET,
        "fb_exchange_token": access_token,
    }
    response = requests.get(exchange_url, params=params)
    data = response.json()
    access_token=data['access_token']
    print('After',access_token)
    companyfacebook.page_access_token=access_token
    companyfacebook.last_update_time=timezone.now()
    companyfacebook.save()

def exchangeTiktokToken(refresh_token,companytiktok):
    # Define the URL and payload for the refresh request
    url = "https://open.tiktokapis.com/v2/oauth/token/"
    payload = {
        "client_key": settings.TIKTOK_CLIENT_ID,
        "client_secret": settings.TIKTOK_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
# Set the correct headers
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, data=payload,verify=False,headers=headers)

    # Check the response status
    if response.status_code == 200:
        # If successful, parse the response JSON
        data = response.json()
        print(data)
        new_access_token = data['access_token']
        new_refresh_token = data['refresh_token']
        expires_in = data['expires_in']
        companytiktok.access_token=new_access_token
        companytiktok.refresh_token=new_refresh_token
        companytiktok.last_update_time=timezone.now()
        companytiktok.token_expiry=timezone.now()+timedelta(seconds=expires_in)
        companytiktok.save()
        def tiktok_profile_stat(access_token):
            url = 'https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name,username,follower_count,likes_count'
            headers = {
                'Authorization': f'Bearer {access_token}'
            }
            response = requests.get(url, headers=headers)
            print(response.json())
            dta = response.json().get('data', {}).get('user')
            return {
                'user_id': dta.get('union_id'),
                'ppic': dta.get('avatar_url'),
                'disp_name': dta.get('display_name'),
                'u_name': dta.get('username'),
                'f_count': dta.get('follower_count'),
                'l_count': dta.get('likes_count')
            }

        data = tiktok_profile_stat(new_access_token)
        ctk=companytiktok
        ctk.active = True
        ctk.linked = True
        ctk.account_name = data['disp_name']
        ctk.account_username = data['u_name']
        ctk.profile_url = data['ppic']
        ctk.account_id = data['user_id']
        ctk.followers_count.append(data['f_count'])
        ctk.likes_count.append(data['l_count'])
        ctk.save()

        # Print the new tokens
        print(f"New Access Token: {new_access_token}")
        print(f"New Refresh Token: {new_refresh_token}")
        print(f"Expires In: {expires_in} seconds")
    else:
        print(f"Error refreshing token: {response.status_code}")
        print(response.content)    
        
        
class Command(BaseCommand):
    help = 'Runs a background task'

    def handle(self, *args, **kwargs):
        while True:
            self.manageAll()
            # break
            # Add your background logic here
            time.sleep(10)  # Sleep for a while before running again
    def manageAll(self):
        ''' calls all fuunctions below'''
        self.updateAccessTokens()
        self.uploadScheduledContent()
        pass
    # updating the access tokens for every account
    def updateAccessTokens(self):
        '''Update facebook, instagram and tiktok access tokens '''
        for c in CompanyFacebook.objects.all():
            access_token=c.page_access_token
            lastupd = c.last_update_time
            
            tdiff=(timezone.now()-lastupd).total_seconds()/3600
            if tdiff>12:
                print('updating facebook access token')
                tv=threading.Thread(target=exchangeFacebookToken,kwargs={'access_token':access_token,'companyfacebook':c},daemon=True)
                tv.start()
        
        # update tiktok
        for t in CompanyTiktok.objects.all():
            ref=t.refresh_token
            lastupd = c.last_update_time
            tdiff=(timezone.now()-lastupd).total_seconds()/3600
            if tdiff>12:
                tv=threading.Thread(target=exchangeTiktokToken,kwargs={'refresh_token':ref,'companytiktok':t},daemon=True)
                tv.start()
            
    
    def uploadScheduledContent(self):
        '''check and upload scheduled content'''
        pass
    
    def checkUsersSubscription(self):
        ''' updates users subscription status'''
        pass
    def updatePostEngagement(self):
        ''' every 10 minutes, update the engagement in background, comments,likes notifications'''
        pass