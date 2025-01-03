from django.core.management.base import BaseCommand
import time
import os
import sys
import django 
import threading
import requests
import traceback
import praw
import ffmpeg
import boto3
import tempfile
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reputation_fow.settings')
django.setup()
# Get the current directory of the script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Move up three directories
parent_dir = os.path.abspath(os.path.join(current_dir, '../../..'))

# Add the parent directory to sys.path
sys.path.append(parent_dir)
import mimetypes
from reputation_app.models import *
from django.conf import settings

            
s3_client = boto3.client(
    's3',
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_S3_REGION_NAME,
)

def postReddit(title, description, subs, hasMedia,spoiler_tag,nsfw_tag, files,  red_refresh_token,pst,cr):
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
        all_files = []
        if hasMedia:
            # save to local file
            # Initialize your S3 client
            s3 =  boto3.client(
                's3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_S3_REGION_NAME,
            )
            
            # Bucket and file details
            bucket_name = settings.AWS_STORAGE_BUCKET_NAME
            print('files',files)
            for file in files: 
                s3_file_key = file
                content_type = mimetypes.guess_type(s3_file_key)[0] 
                # Temporary file download
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(s3_file_key)[-1]) as temp_file:
                    local_file_path = temp_file.name
                    all_files.append({'image_path':local_file_path,'content_type':content_type})
                    s3.download_file(bucket_name, s3_file_key, local_file_path)        
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
                        if len(all_files) == 1:
                            # check if image or video and upload accoordingly
                            f = all_files[0]['image_path']
                            content_type = all_files[0]['content_type']
                            if content_type.startswith("image/"):
                                # check image posting
                                if subreddit.allow_images:
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
                                cr.save()

                            elif content_type.startswith("video/"):
                                print('submitting video')
                                if subreddit.allow_videos:
                                    try:
                                        submission = subreddit.submit_video(
                                            title=description,
                                            video_path=f,
                                            timeout=60,
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
                                cr.save()

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
                                cr.save()
                                
                        else:
                            # # Submit a gallery post
                            if subreddit.allow_images:
                                fles=all_files
                                # for fle in all_files:
                                #     fles.append(fle['image_path'])
                                try:
                                    submission = subreddit.submit_gallery(
                                        title=description,
                                        images=fles,
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
                                        cover_image_url = gallery_data[cover_image_id]['p'][-1]['u']  # Get the first preview
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
                                        pass
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
                            cr.save()

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
                        cr.save()
                    break
            # get the selected flairs
        cred = CompanyRedditPosts.objects.filter(post_id=pst.post_id).first()
        if cred:
            cred.subs=sub_tr
            cred.save()
        else:
            cred = CompanyRedditPosts(
            post_id=pst.post_id,
            nsfw_tag=nsfw_tag,
            spoiler_flag=spoiler_tag,
            target_subs=subs,
            subs=sub_tr)
            cred.save()
            # subreddit = reddit.subreddit('test')
            # # Submit the post to the chosen subreddit
            # post = subreddit.submit(title, selftext=description)

        if failed_publish and published:
            pst.is_published = True
            pst.partial_publish = True
            pst.is_scheduled=False
            pst.date_uploaded=timezone.now()
            for res in fail_reasons:
                pst.failure_reasons.append(res)
            pst.save()
        elif not failed_publish and published:
            pst.date_uploaded=timezone.now()
            pst.is_published = True
            pst.is_scheduled=False
            pst.save()
        elif failed_publish and not published:
            pst.date_uploaded=timezone.now()
            pst.is_scheduled=False
            if not pst.is_published:
                pst.has_failed = True
            pst.failure_reasons.extend(fail_reasons)
            pst.save()
    
    except:
        print()
        pst.is_published=False
        pst.has_failed=True
        pst.is_scheduled=False
        pst.date_uploaded=timezone.now()
        pst.save()
    
    # remove all temporary files
    for t in all_files:
        if os.path.exists(t['image_path']):
            os.path.remove(t['image_path'])

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

    else:
        print(f"Error refreshing token: {response.status_code}")
        print(response.content)    

def postFacebook(media,post_id ):
    # API endpoint for creating a post
    cops = CompanyPosts.objects.filter(post_id=post_id).first()
    if not cops:
        print('Could not get the sending post')
        return
    title=cops.title 
    description=cops.description
    cfb=CompanyFacebook.objects.filter(company=cops.company).first()
    if not cfb:
        print('Could not get the FB COMPANY ')
        return
    
    has_media=cops.has_media
    access_token=cfb.page_access_token
    page_id=cfb.page_id
    # save video post
    url = f"https://graph.facebook.com/v21.0/{page_id}/feed"

    cfb_pst = CompanyFacebookPosts.objects.filter(post_id=post_id).first()
    if not cfb_pst:
        return
    to_stories=cfb_pst.to_stories
    to_post=cfb_pst.to_post
    if cops.is_video:
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
                    cops.is_scheduled = False
                    cops.save()
                    cops.is_published = True
                    cops.save()

                    print(response.json())
                else:
                    if not cops.partial_publish:
                        cops.has_failed = True
                        cops.is_scheduled = False
                        cops.failure_reasons.append('Failed to post to facebook')
                        cops.save()
                    print(f"Error creating post: {response.status_code}")
                    print(response.json())
            except:
                if not cops.partial_publish:
                    cops.has_failed = True
                    cops.is_scheduled = False
                    cops.failure_reasons.append('Failed to post to facebook')

def postContent(post):
    gallery_items=[]
    if post.has_media:
        # print('post has media')
        ul=UploadedMedia.objects.filter(post=post)
        for p in ul:
            gallery_items.append(p.media.name)
        # print(gallery_items)
    else:
        pass
        # print('Has no media') 
    pltforms=post.platforms
    if not post.is_scheduled:
        return
    post.is_scheduled=False
    post.save()

    for pltfrm in pltforms:
        if 'reddit' in pltfrm.lower():
            crp=CompanyRedditPosts.objects.filter(post_id=post.post_id).first()
            if not crp:
                return 
            cr=CompanyReddit.objects.filter(company=post.company).first()
            redThread = threading.Thread(target=postReddit, daemon=True, kwargs={
                'title': post.title,
                'description': post.description,
                'subs': crp.target_subs,
                'hasMedia': post.has_media,
                'files': gallery_items,
                'red_refresh_token': cr.refresh_token,
                'spoiler_tag':crp.spoiler_flag,
                'nsfw_tag':crp.nsfw_tag,
                'pst':post,
                'cr':cr,
            })
            redThread.start()
            
        if 'facebook' in pltfrm.lower():
            fbThread = threading.Thread(target=postFacebook, daemon=True, kwargs={
                'media': gallery_items,
                'post_id': post.post_id,
            })
            fbThread.start()
            print('FACEBOOK POSTED')
        if 'tiktok' in pltfrm.lower():
            pass
        if 'instagram' in pltfrm.lower():
            pass

def delete_file_from_s3(file_key):
    try:
        # Delete the file from S3
        s3_client.delete_object(
            Bucket=settings.AWS_STORAGE_BUCKET_NAME,
            Key=file_key,
        )
                
        return {"message": "File deleted successfully."}
    except Exception as e:
        return {"error": str(e)}
    
    # import magic 


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
        self.checkUsersSubscription()
        self.removes3Media()
        
    # updating the access tokens for every account
    def updateAccessTokens(self):
        '''Update facebook, instagram and tiktok access tokens '''
        for c in CompanyFacebook.objects.all():
            access_token=c.page_access_token
            lastupd = c.last_update_time
            
            tdiff=(timezone.now()-lastupd).total_seconds()/3600
            if tdiff>12: # update every 12 hours
                print('updating facebook access token')
                tv=threading.Thread(target=exchangeFacebookToken,kwargs={'access_token':access_token,'companyfacebook':c},daemon=True)
                tv.start()

        # update tiktok
        for t in CompanyTiktok.objects.all():
            ref=t.refresh_token
            lastupd = c.last_update_time
            tdiff=(timezone.now()-lastupd).total_seconds()/3600
            if tdiff>12:# update every 12hours
                tv=threading.Thread(target=exchangeTiktokToken,kwargs={'refresh_token':ref,'companytiktok':t},daemon=True)
                tv.start()
            
    
    def uploadScheduledContent(self):
        '''check and upload scheduled content'''
        sps=CompanyPosts.objects.filter(is_scheduled=True)
        for sp in sps:
            tnw=timezone.now()
            tt=sp.date_scheduled
            
            # should be within a minute
            tdiff=(tt-tnw).total_seconds()/60 
            if tdiff <= 0:
                tts= threading.Thread(target=postContent,daemon=True,kwargs={'post':sp})
                tts.start()
        
    
    def checkUsersSubscription(self):
        ''' updates users subscription status'''
        for cp in Company.objects.all():
            if cp.company_active_subscription:
                sub_dte=cp.company_subscription_date
                tdiff=(tnw-sub_dte).total_seconds()
                if tdiff/86400 <30:
                    cp.company_active_subscription=False
                    cp.save()
                    # send subscription expiry email
                if tdiff/86400 <23:
                    # send subscription expiry reminder email 1 week before
                    pass
            if cp.company_free_trial:
                # check if already expired
                datex= cp.company_free_trial_expiry
                tnw=timezone.now()
                tdiff=(tnw-datex).total_seconds()
                if tdiff>0:
                    cp.company_free_trial=False
                    cp.save()
                
    def updatePostEngagement(self):
        ''' every 10 minutes, update the engagement in background, comments,likes notifications'''
        pass
    def removes3Media(self):
        for cp in CompanyPosts.objects.filter(is_published=True):
            for upl in UploadedMedia.objects.filter(post=cp):
                delThead=threading.Thread(target=delete_file_from_s3,kwargs={'file_key':upl.media.name},daemon=True)
                delThead.start()
        
        # check for failed and greater than 5 days schedule period
        for cps in CompanyPosts.objects.filter(has_failed=True):
            for upl in UploadedMedia.objects.filter(post=cp):
                dt_uplded=cps.date_uploaded
                tnw=(timezone.now()-dt_uplded).total_seconds()/86400
                if tnw >=7:
                    delThead=threading.Thread(target=delete_file_from_s3,kwargs={'file_key':upl.media.name},daemon=True)
                    delThead.start()

            
        pass