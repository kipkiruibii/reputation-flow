from django.db import models
from django.contrib.auth.models import User 
from django.utils import timezone

class MemberProfile(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    email=models.CharField(max_length=100)
    def __str__(self) -> str:
        return self.user.username
    
    
class Company(models.Model):
    company_name=models.CharField(max_length=255)
    company_profile=models.TextField(default='')
    date_created=models.DateField(default=timezone.now)
    company_about=models.TextField(default='')
    company_phone=models.CharField(max_length=30)
    company_address=models.TextField(default='')
    city =models.TextField(default='')
    state=models.TextField(default='')
    country=models.TextField(default='')
    zipcode=models.TextField(default='')
    company_website=models.TextField(default='')
    def __str__(self) -> str:
        return self.company_name
 
class CompanyMember(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    member=models.ForeignKey(MemberProfile,on_delete=models.CASCADE)
    role=models.TextField(default='')
    active=models.BooleanField(default=True)
    permissions=models.JSONField(default=dict())
    
    def __str__(self):
        return f'{self.company.name} {self.member.user.username}'
       
class CompanyContacts(models.Model):
    company=models.ForeignKey(Company,on_delete=models.CASCADE)
    instagram=models.TextField(default='',null=True)
    facebook=models.TextField(default='',null=True)
    whatsapp=models.TextField(default='',null=True)
    twitter=models.TextField(default='',null=True)
    email=models.TextField(default='',null=True)
    linkedin=models.TextField(default='',null=True)
    youtube=models.TextField(default='',null=True)
    
    def __str__(self):
        return self.company.company_name

class CompanyInstagram(models.Model):
    token=models.TextField(default='')
    active=models.BooleanField(default=False)
    linked=models.BooleanField(default=False)
    
     
class CompanyPosts(models.Model):
    platforms=models.JSONField(default=dict(platform= None,uploaded=None,comment=None))
    content=models.TextField(default='')
    is_uploaded=models.BooleanField(default=True)
    has_media=models.BooleanField(default=True)
    date_uploaded=models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.content


class UploadedMedia(models.Model):
    post=models.ForeignKey(CompanyPosts,on_delete=models.CASCADE)
    media=models.ImageField(upload_to='scheduled_media/')


class CompanyReviews(models.Model):
    content=models.TextField(default='')
    commentor=models.CharField(max_length=100)
    date_commented=models.DateTimeField(default=timezone.now)
    category=models.CharField(max_length=100) # can be review/ question/unidentified. obtained from mention/reply to post
    platform=models.TextField(default='')
 
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
    
    
       
