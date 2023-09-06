from django.shortcuts import render, redirect
from django.contrib.auth.models import User, auth
from django.contrib import messages
from .models import UserProfile
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.http import HttpResponse
from django.conf import settings
import random 
import string 
from .helpers import send_forget_password_mail
import uuid

# my imported moduled used
from django.core.exceptions import *
from django.core.mail import EmailMessage
from .forms import *
from django.contrib.auth import update_session_auth_hash,get_user_model
from .token import *
from django.contrib.sites.shortcuts import get_current_site


# Create your views here.
@login_required(login_url='signin')
def home(request):
    return render(request, 'uoe/uoe.html')
@login_required(login_url='signin')
def about(request):
    return render(request, 'uoe/about.html')
@login_required(login_url='signin')
def blog(request):
    return render(request, 'uoe/blog.html')
@login_required(login_url='signin')
def contact(request):
    return render(request, 'uoe/contact.html')
@login_required(login_url='signin')
def course(request):
    return render(request, 'uoe/course.html')

def signin(request):
    if request.method == 'POST':                
        user_obj = auth.authenticate(username=request.POST.get('username'),password=request.POST.get('password'))
        if user_obj is not None:
            auth.login(request, user_obj)
            return redirect('home')
        else:
            messages.info(request, 'Invalid credentials!')
            return redirect('signin')  
    return render(request, 'uoe/signin.html')



def signup(request):
    if request.method == 'POST':
        if request.POST.get('password1') == request.POST.get('password2'):
            messages.error(request, 'Password mismatch')
        if User.objects.filter(username=request.POST.get('username')).exists():
            messages.info(request, 'Username taken!')
        if User.objects.filter(email=request.POST.get('email')).exists():
            messages.info(request, 'Email already exists!')
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            profile_obj = UserProfile.objects.create(username=request.POST.get('username'), email=request.POST.get('email'))
            profile_obj.save()
            messages.success(request, 'an account has been created for you')
            return redirect('signin')      
    return render(request, 'uoe/signup.html')


def reset(request):
    if request.method == 'POST':
        #validating user with email and send mail
        try:
            user = UserProfile.objects.filter(email = request.POST.get('email'))
            user1 = UserProfile.objects.get(email = request.POST.get('email'))
            email = user[0].email
            mail_subject = 'UOE - Your forget password link'
            email_from = settings.EMAIL_HOST_USER
            message = render_to_string('uoe/email_template.html', {
                'domain': get_current_site(request).domain,
                'uid': urlsafe_base64_encode(force_bytes(user1.pk)),
                'token': PasswordTokenGenerator.make_token(user1),
                'protocol': 'https' if request.is_secure() else 'http',

            })
            email = EmailMessage(mail_subject, message,email_from, to=[email])
            email.send(fail_silently=False)
            messages.success(request, 'An email has been sent to you   ')
        #message to user if not found in database   
        except ObjectDoesNotExist:
            messages.error(request, 'An account with ' + request.POST.get('email') + ' not found, re-try')        
    return render(request, 'uoe/reset.html')





def change_password(request, token, uidb64):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk = uid)
 
    except:
        user = None
    if user is not None and PasswordTokenGenerator.check_token(user, token):
        if request.method == 'POST':
            form = CustomSetPasswordForm(user=user, data=request.POST)
            new_password = request.POST.get('password')
            confirm_password = request.POST.get('password1')
            if new_password != confirm_password:
                messages.error(request, 'Password do not match')
            if form.is_valid():
                form.save()
                print(111)
                messages.success(request, 'password has been successfully changed, you can now login in with the new passord')
                return redirect('signin')
    form = CustomSetPasswordForm(user=user, data=request.POST)
       
            
    return render(request, 'uoe/change_password.html', {'form':form})
