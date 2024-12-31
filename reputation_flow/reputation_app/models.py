from django.db import models
from django.contrib.auth.models import User 
from django.utils import timezone
from datetime import timedelta,datetime

class SiteAnalytics(models.Model):
    page_visited=models.TextField(default='')
    device=models.TextField(default='')
    date_visited=models.DateTimeField(default=timezone.now())
    request_header=models.TextField(default='')    
    country=models.TextField(default='')    
    ip_address=models.TextField(default='')    
    city=models.TextField(default='')    
    browser=models.TextField(default='')    
    os=models.TextField(default='')    
    location=models.JSONField(default='')  # {latitude:1222,longitude:133}  
    is_vpn=models.BooleanField(default=False)  
    is_mobile=models.BooleanField(default=False)  
    is_tablet=models.BooleanField(default=False)  
    is_pc=models.BooleanField(default=False)  
    
    def __str__(self) -> str:
        return self.user.username
    
    
class MemberProfile(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    email=models.CharField(max_length=100)
    def __str__(self) -> str:
        return self.user.username
    
class MemberPP(models.Model):
    member=models.ForeignKey(MemberProfile,on_delete=models.CASCADE)
    pic=  models.ImageField(upload_to='member_profile_picture/')  
    def __str__(self):
        return self.member.user.username + ' Profile Picture'
    
    
class Company(models.Model):
    company_name=models.CharField(max_length=255)
    company_id=models.CharField(max_length=255,default='id')
    company_link=models.CharField(max_length=255,default='link')
    company_link_name=models.CharField(max_length=255,default='link')
    company_category=models.TextField(default='')
    company_storage=models.IntegerField(default=0)
    company_subscription=models.TextField(default='')
    company_review_link=models.TextField(default='')
    company_subscription_tier=models.IntegerField(default=1)
    company_free_trial=models.BooleanField(default=True)
    company_free_trial_expiry=models.DateTimeField(default=timezone.now() + timezone.timedelta(days=5))
    company_subscription_date=models.DateTimeField(default=timezone.now())
    company_active_subscription=models.BooleanField(default=False)
    company_show_page=models.BooleanField(default=True)
    company_enable_ai=models.BooleanField(default=False)
    date_created=models.DateField(default=timezone.now)
    company_about=models.TextField(default='',null=True,blank=True)
    company_phone=models.CharField(max_length=30,blank=True,null=True)
    company_address=models.TextField(default='',blank=True,null=True)
    company_address2=models.TextField(default='',null=True,blank=True)
    city =models.TextField(default='')
    state=models.TextField(default='')
    country=models.TextField(default='')
    zipcode=models.TextField(default='')
    company_website=models.TextField(default='',null=True,blank=True)
    
    def __str__(self) -> str:
        return self.company_name

class CompanyBotChats(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    sender=models.TextField(default='',null=True,blank=True)
    message=models.TextField(default='',null=True,blank=True)
    date_sent=models.DateTimeField(default=timezone.now())
    conversation_id=models.TextField(default='',null=True,blank=True)
    
    def __str__(self) -> str:
        return 'BOT CHAT '+self.company_name

class CompanyProfilePicture(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    p_pic=models.ImageField(upload_to='company_profile/')
    def __str__(self) -> str: 
        return self.company.company_name + ' Profile Picture'
  
class CompanyTeam(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    team_name=models.CharField(max_length=50)
    team_about=models.TextField(default='')
    date_created=models.DateField(default=timezone.now)
    members=models.ManyToManyField(MemberProfile,related_name='team_members')
    
    def __str__(self):
        return self.team_name
    
class CompanyTeamInviteLinks(models.Model):
    team=models.ForeignKey(CompanyTeam,on_delete=models.CASCADE)
    link=models.CharField(max_length=255)
    permissions=models.JSONField(default=list)
    active=models.BooleanField(default=True)
    num_members=models.IntegerField(default=0)
    max_members=models.IntegerField(default=0)
    date_created=models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return self.team.team_name  
    
class CompanyTeamFiles(models.Model):
    team=models.ForeignKey(CompanyTeam,on_delete=models.CASCADE)
    creator_id=models.CharField(max_length=255)
    file_name=models.TextField(default='')
    description=models.TextField(default='')
    not_sent=models.BooleanField(default=True)
    sent_drafts=models.BooleanField(default=False)
    sent_back=models.BooleanField(default=False)
    approved=models.BooleanField(default=False)
    date_created=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.file_name

class CompanyFeatureRequest(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    title=models.TextField(default='')
    details=models.TextField(default='')
    upvotes=models.IntegerField(default=0)
    feature_introduced=models.BooleanField(default=False)
    date_created=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.company.company_name +' TITLE '+ self.title 
    
class CompanyKnowledgeBase(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    training_done=models.BooleanField(default=False)
    training_inprogress=models.BooleanField(default=False)
    date_uploaded=models.DateTimeField(default=timezone.now)
    file=models.FileField(upload_to='training_data/')
    def __str__(self):
        return 'Training: '+ self.company.company_name
    
    
class UploadedFiles(models.Model):
    file=models.FileField(upload_to='uploaded_files/')
    team=models.ForeignKey(CompanyTeamFiles,on_delete=models.CASCADE) 
    
class CompanyTeamAnnouncements(models.Model):
    team=models.ForeignKey(CompanyTeam,on_delete=models.CASCADE)
    title=models.TextField(default='')
    content=models.TextField(default='')
    creator=models.ForeignKey(MemberProfile,on_delete=models.DO_NOTHING)
    date_created=models.DateTimeField(default=timezone.now)  
    
    def __str__(self):
        return self.team.team_name+' TITLE '+ self.title 
    
    
class CompanyTeamActivity(models.Model):
    team=models.ForeignKey(CompanyTeam,on_delete=models.CASCADE)
    title=models.TextField(default='')
    date_created=models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return self.team.team_name + ' TITLE '+ str(self.date_created)
                     
class CompanyTeamChat(models.Model):
    team=models.ForeignKey(CompanyTeam,on_delete=models.CASCADE)
    sender=models.ForeignKey(MemberProfile,on_delete=models.CASCADE)
    message=models.TextField(default='')
    date_sent=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.team.team_name
    
        
class CompanyMember(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    member=models.ForeignKey(MemberProfile,on_delete=models.CASCADE)
    role=models.TextField(default='')
    active=models.BooleanField(default=True)
    is_admin=models.BooleanField(default=False)
    permissions=models.JSONField(default=dict(), blank=True,null=True)
    
    def __str__(self):
        return f'{self.company.company_name} {self.member.user.username}'
       
class CompanyContacts(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    instagram=models.TextField(default='',null=True, blank=True)
    facebook=models.TextField(default='',null=True, blank=True)
    whatsapp=models.TextField(default='',null=True, blank=True)
    twitter=models.TextField(default='',null=True, blank=True)
    tiktok=models.TextField(default='',null=True, blank=True)
    email=models.TextField(default='',null=True, blank=True)
    linkedin=models.TextField(default='',null=True, blank=True)
    youtube=models.TextField(default='',null=True, blank=True)
    
    def __str__(self):
        return self.company.company_name

class CompanyInstagram(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE,null=True,blank=True)
    active=models.BooleanField(default=False)
    linked=models.BooleanField(default=False)
    short_lived_token=models.TextField(default='')
    long_lived_token=models.TextField(default='')
    token_expiry=models.DateField(default=timezone.now() + timezone.timedelta(days=60))
    account_name=models.TextField(default='')
    profile_url=models.TextField(default='')
    account_id=models.TextField(default='')
    followers_trend=models.JSONField(default=list)
    impressions=models.JSONField(default=list)
    reach=models.JSONField(default=list)
    last_update_time=models.DateTimeField(default=timezone.now)
    date_linked= models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.company.company_name+ ' ' + self.account_name

class CompanyFacebook(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE,null=True,blank=True)
    active=models.BooleanField(default=False)
    linked=models.BooleanField(default=False)
    page_id=models.TextField(default='')
    page_access_token=models.TextField(default='')
    short_lived_token=models.TextField(default='')
    long_lived_token=models.TextField(default='')
    token_expiry=models.DateField(default=timezone.now() + timezone.timedelta(days=60))
    account_name=models.TextField(default='')
    profile_url=models.TextField(default='')
    account_id=models.TextField(default='')
    pages=models.JSONField(default=list) # [{'name':str,'id':str,'access_token':str,'profile_url':str,'data':{'':}}]
    followers_trend=models.JSONField(default=list)
    impressions=models.JSONField(default=list)
    profile_views=models.JSONField(default=list)
    reach=models.JSONField(default=list)
    page_fans=models.JSONField(default=list)
    page_views_total=models.JSONField(default=list)
    last_update_time=models.DateTimeField(default=timezone.now)
    date_linked= models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.company.company_name+ ' '+self.account_name

class CompanyTiktok(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE,null=True,blank=True)
    active=models.BooleanField(default=False)
    linked=models.BooleanField(default=False)
    access_token=models.TextField(default='')
    refresh_token=models.TextField(default='')# update the access token every 1 day
    token_expiry=models.DateField(default=timezone.now() + timezone.timedelta(days=60))
    account_name=models.TextField(default='')
    account_username=models.TextField(default='')
    profile_url=models.TextField(default='')
    account_id=models.TextField(default='')
    account_type=models.TextField(default='')
    followers_count=models.JSONField(default=list)
    likes_count=models.JSONField(default=list)
    profile_views=models.JSONField(default=list)
    reach=models.JSONField(default=list)
    last_update_time=models.DateTimeField(default=timezone.now)
    date_linked= models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.company.company_name + ' ' + self.account_name
    
    
class CompanyReddit(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE,null=True,blank=True)
    active=models.BooleanField(default=False)
    linked=models.BooleanField(default=False)
    access_token=models.TextField(default='')
    refresh_token=models.TextField(default='')# update the access token every 1 day
    account_username=models.TextField(default='')
    profile_url=models.TextField(default='')
    subs=models.JSONField(default=list) #[{'subreddit:string,'flairs':[{'name':string,'id':string,'selected':bool}]}]
    comment_karma=models.TextField(default='')
    link_karma=models.TextField(default='')
    last_updated=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.company.company_name + ' ' + self.account_username
    
class CompanyPrivateConversation(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    sender=models.CharField(max_length=255,null=True,blank=True)
    sender_id=models.CharField(max_length=255,null=True,blank=True)
    sender_profile=models.TextField(default='')
    last_message_time=models.DateTimeField(default=timezone.now)
    platform=models.CharField(max_length=255,null=True,blank=True)
    conversation_id=models.CharField(max_length=255,null=True,blank=True)
    def __str__(self):
        return self.sender + ' ' + self.platform
 
class ConversationMessages(models.Model):
    conversation_id=models.CharField(max_length=255,null=True,blank=True)
    message_id=models.CharField(max_length=255,null=True,blank=True)
    sender=models.CharField(max_length=255,null=True,blank=True)
    sender_id=models.CharField(max_length=255,null=True,blank=True)
    message=models.TextField(default='')
    is_me=models.BooleanField(default=False)
    created_at=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.sender + ' ' 

    
class CompanyPosts(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE,null=True,blank=True)
    post_id=models.CharField(max_length=255,null=True,blank=True)
    platforms=models.JSONField(default=list)
    tags=models.JSONField(default=list)
    title=models.TextField(default='')
    description=models.TextField(default='')
    media_thumbnail=models.TextField(default='')
    comment_count=models.IntegerField(default=0)
    engagement_count=models.IntegerField(default=0)
    is_scheduled=models.BooleanField(default=False)
    is_published=models.BooleanField(default=False)
    partial_publish=models.BooleanField(default=False)
    has_failed=models.BooleanField(default=False)
    failure_reasons=models.JSONField(default=list)
    has_media=models.BooleanField(default=True)
    is_video=models.BooleanField(default=True)
    date_uploaded=models.DateTimeField(default=timezone.now)
    date_scheduled=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.description
    
class CompanyInstagramPosts(models.Model):
    post_id=models.CharField(max_length=255)
    to_stories=models.BooleanField(default=False)
    to_reels=models.BooleanField(default=False)
    to_posts=models.BooleanField(default=False)
    run_copyright=models.BooleanField(default=True)
    has_copyright=models.BooleanField(default=False)
    is_published=models.BooleanField(default=False)
    comment_count=models.IntegerField(default=0)
    like_count=models.IntegerField(default=0)
    impression_count=models.IntegerField(default=0)
    engagement_count=models.IntegerField(default=0)
    views_count=models.IntegerField(default=0)
    location_tags=models.TextField(default='')
    product_tags=models.TextField(default='')
    post_link=models.TextField(default='')

    def __str__(self):
        return self.post_id
    
class CompanyFacebookPosts(models.Model):
    post_id=models.CharField(max_length=255)
    to_stories=models.BooleanField(default=False)
    to_reels=models.BooleanField(default=False)
    to_posts=models.BooleanField(default=False)
    run_copyright=models.BooleanField(default=True)
    has_copyright=models.BooleanField(default=False)
    is_published=models.BooleanField(default=False)
    comment_count=models.IntegerField(default=0)
    like_count=models.IntegerField(default=0)
    impression_count=models.IntegerField(default=0)
    post_impression_type=models.JSONField(default=dict)#{'post_impressions_unique':int,'post_impressions_paid':int,'post_impressions_fan':int,'post_impressions_organic':int,'post_impressions_viral':int,'post_impressions_nonviral':int}
    post_clicks=models.IntegerField(default=0)
    engagement_count=models.IntegerField(default=0)
    views_count=models.IntegerField(default=0)
    location_tags=models.TextField(default='')
    product_tags=models.TextField(default='')
    post_link=models.TextField(default='')
    content_id=models.TextField(default='')
    parent_post_id=models.TextField(default='')
    
    def __str__(self):
        return self.post_id
class CompanyRedditPosts(models.Model):
    post_id=models.CharField(max_length=255)
    nsfw_tag=models.BooleanField(default=False)
    spoiler_flag=models.BooleanField(default=False)
    brand_flag=models.BooleanField(default=False)
    subs = models.JSONField(default=dict)# [{'sub_name':str,'id':str,'link':str,'comments':int,'upvotes':int,'upvote_ratio':int,'crossposts':int}]
    target_subs=models.JSONField(default=list)
    post_link=models.TextField(default='')
    agg_engagement_count = models.IntegerField(default=0)
    last_updated=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.post_id

class CompanyTiktokPosts(models.Model):
    post_id=models.CharField(max_length=255,null=True,blank=True)
    video_id=models.CharField(max_length=255,null=True,blank=True)
    run_copyright=models.BooleanField(default=True,null=True,blank=True)
    has_copyright=models.BooleanField(default=False,null=True,blank=True)
    is_published=models.BooleanField(default=False,null=True,blank=True)
    reasons=models.TextField(default='',null=True,blank=True)
    mentions=models.TextField(default='',null=True,blank=True)
    cover_image_url=models.TextField(default='',null=True,blank=True)
    post_link=models.TextField(default='',null=True,blank=True)
    engagement_count=models.IntegerField(default=0,null=True,blank=True)
    comment_count=models.IntegerField(default=0,null=True,blank=True)
    share_count=models.IntegerField(default=0,null=True,blank=True)
    views_count=models.IntegerField(default=0,null=True,blank=True)
    average_watch_time=models.IntegerField(default=0,null=True,blank=True)
    reach=models.IntegerField(default=0,null=True,blank=True)
    duet_count=models.IntegerField(default=0,null=True,blank=True)
    stitch_count=models.IntegerField(default=0,null=True,blank=True)
    completion_rate=models.IntegerField(default=0,null=True,blank=True)
    click_through_rate=models.IntegerField(default=0,null=True,blank=True)
    profile_visits=models.IntegerField(default=0,null=True,blank=True)
    def __str__(self):
        return self.post_id

class CompanyRedditSubs(models.Model):
    sub_name=models.CharField(max_length=255)
    full_name=models.CharField(max_length=255)
    description=models.TextField(default='')
    subscriber_count=models.TextField(default='')
    user_is_banned=models.BooleanField(default=False,null=True)
    sub_rules=models.JSONField(default=list)#[{'rule':str,'description':str}]
    last_updated=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.sub_name

class CompanyPostsComments(models.Model):
    post=models.ForeignKey(CompanyPosts,on_delete=models.CASCADE)
    comment_id=models.CharField(max_length=255,null=True,blank=True)
    platform=models.CharField(max_length=255,null=True,blank=True)
    author=models.CharField(max_length=255,null=True,blank=True)
    author_profile=models.TextField(default='',null=True,blank=True)
    message=models.TextField(default='',null=True,blank=True)
    is_op=models.BooleanField(default=False,null=True,blank=True)
    like_count=models.IntegerField(default=0,null=True,blank=True)
    reply_count=models.IntegerField(default=0,null=True,blank=True)
    is_published=models.BooleanField(default=False,null=True,blank=True)
    date_updated=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.comment_id
    
class CompanyPostsCommentsReplies(models.Model):
    parent_comment_id=models.CharField(max_length=255,null=True,blank=True)
    comment_id=models.CharField(max_length=255,null=True,blank=True)
    author=models.CharField(max_length=255,null=True,blank=True)
    author_profile=models.TextField(default='',null=True,blank=True)
    message=models.TextField(default='',null=True,blank=True)
    is_op=models.BooleanField(default=False,null=True,blank=True)
    like_count=models.IntegerField(default=0,null=True,blank=True)
    reply_count=models.IntegerField(default=0,null=True,blank=True)
    is_published=models.BooleanField(default=False,null=True,blank=True)
    date_updated=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return f'{self.comment_id} - REPLY TO {self.parent_comment_id}'

class UploadedMedia(models.Model):
    post=models.ForeignKey(CompanyPosts,on_delete=models.CASCADE)
    media=models.FileField(upload_to='scheduled_media/')
    def __str__(self):
        return self.post.title

class CompanyReviews(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE,null=True,blank=True)
    content=models.TextField(default='')
    commentor_profile=models.TextField(default='')
    link=models.TextField(default='')
    commentor=models.CharField(max_length=100)
    is_published=models.BooleanField(default=False,null=True,blank=True)
    is_positive=models.BooleanField(default=False,null=True,blank=True)
    is_negative=models.BooleanField(default=False,null=True,blank=True)
    is_neutral=models.BooleanField(default=False,null=True,blank=True)
    date_commented=models.DateTimeField(default=timezone.now)
    category=models.CharField(max_length=100) # can be review/ question/unidentified. obtained from mention/reply to post
    platform=models.TextField(default='')
    def __str__(self):
        return self.platform

class MemberMessages(models.Model):
    sender=models.ForeignKey(CompanyMember,on_delete=models.CASCADE)
    recipients=models.ManyToManyField(CompanyMember,related_name='recipient')   
    date_sent=models.DateTimeField(default=timezone.now)
    conversation_id=models.IntegerField(default=0)
    
    def __str__(self):
        return self.sender.member.user.username
    
    
      
class MessageReplies(models.Model):
    conversation_id=models.IntegerField(default=0)
    reply_id=models.IntegerField(default=0)
    sender=models.ForeignKey(CompanyMember,on_delete=models.CASCADE,related_name='sending_user')
    recipient=models.ForeignKey(CompanyMember,on_delete=models.CASCADE,related_name='receiving_user')
    message=models.TextField(default='')
    date_sent=models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return self.conversation_id
    
    
       
