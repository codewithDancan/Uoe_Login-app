from django import forms
from django.contrib.auth.forms import UserCreationForm,SetPasswordForm,UserChangeForm

from django.contrib.auth.models import Group,User



        
        
class UserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username','email','password1','password2']
        
        
        
class CustomSetPasswordForm(SetPasswordForm):
    class Meta:
        model = User
        fields = '__all__'