from django import forms
from captcha.fields import CaptchaField

class UserForm(forms.Form):
    username = forms.CharField(max_length=128, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': "Username",'autofocus': ''}))
    password = forms.CharField(max_length=256, widget=forms.PasswordInput(attrs={'class': 'form-control','placeholder': "Password"}))
    captcha = CaptchaField(label='verification code' )


class RegisterForm(forms.Form):
    gender = (
        ('male', "Male"),
        ('female', "Female"),
    )
    username = forms.CharField(label="Username", max_length=128, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': "Username"}))
    password1 = forms.CharField(label="Password", max_length=256, widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': "Password"}))
    password2 = forms.CharField(label="Confirm password", max_length=256, widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': "Confirm password"}))
    email = forms.EmailField(label="E-mail address", widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': "E-mail address"}))
    sex = forms.ChoiceField(label='Gender', choices=gender)
    captcha = CaptchaField(label='Vertification code')