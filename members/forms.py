import re
from django import forms as forms
import django.utils.cache
from django.contrib.auth.models import User
from captcha.fields import ReCaptchaField    
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from members.models import MemberUser
from django.utils.safestring import mark_safe


class RegistrationForm(forms.Form):

    class Meta:
       fields = '__all__' 
    
    handle  = forms.CharField(label='Handle',widget=forms.TextInput(attrs={'size':'35'}), max_length=40)

    password1 = forms.CharField(
      label='Password',
      widget=forms.PasswordInput(attrs={'size':'35'})
      ,help_text = '<br/><p>Password must contain at least one lower chracter, </br>one uppercase character, at least one number, at least one special charater,</br> and be longer than eight charaters.</p>'
    )
    password2 = forms.CharField(
      label='Password (Again)',
      widget=forms.PasswordInput(attrs={'size':'35'})
    )

    email           = forms.EmailField(label='E Mail Address:',widget=forms.TextInput(attrs={'size':'35'}), max_length=254)
    #phone_number    = forms.CharField(label='Phone Number:',widget=forms.TextInput(attrs={'size':'11'}),max_length=11,
    #				help_text = "<p>Please format the Phone Number: as 1NXXNXXXXXX <br/></p>",required=False)
    first_name      = forms.CharField(label='First Name',widget=forms.TextInput(attrs={'size':'35'}),max_length=254,required=False)
    last_name       = forms.CharField(label='Last Name',widget=forms.TextInput(attrs={'size':'35'}),max_length=254,required=False)
    secret_phrase   = forms.CharField(label='Secret phrase',widget=forms.TextInput(attrs={'size':'60'}),max_length=254,help_text='<p>Don\'t forget your secret phrase you might need it</p>')
   
    #captcha = ReCaptchaField(attrs={'theme' : 'clean'})

    def clean_handle(self):

      handle = self.cleaned_data['handle']

      if not re.search(r'^\w+$', handle):
        raise forms.ValidationError(mark_safe('<div class="alert alert-danger">Handle can only contain alphanumeric characters and the underscore.</div>'))

      try:
        MemberUser.objects.get(handle=handle)
      except:
        return handle

      raise forms.ValidationError(mark_safe('<div class="alert alert-danger">Handle is already taken.</div>'))

 #   def clean_phone_number(self):
 #   
 #       phone_number = self.cleaned_data['phone_number']
 #       if not phone_number:
 #           return phone_number


 #       if not re.search(r'^([0-9]{10,11}|)$', phone_number):
 #           raise forms.ValidationError(mark_safe('<div class="alert alert-danger">Cellular Comms Number is invalid please use 1801NXXXXXX format.</div>'))
 #       return phone_number

    def clean_first_name(self):
        first_name = self.cleaned_data['first_name']

        if not first_name:
            return first_name

        if not re.search(r'^[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])?[a-zA-Z0-9]*)*$', first_name):
            raise forms.ValidationError(mark_safe('<div class="alert alert-danger">Common Name contains invalid characters.</div>'))
        return first_name
     

    def clean_last_name(self):
        last_name = self.cleaned_data['last_name']

        if not last_name:
            return last_name

        if not re.search(r'^[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])?[a-zA-Z0-9]*)*$', last_name):
            raise forms.ValidationError(mark_safe('<div class="alert alert-danger">Family Name contains invalid characters.</div>'))
        return last_name

    def clean_secret_phrase(self):
        secret_phrase = self.cleaned_data['secret_phrase']
        return secret_phrase

    def clean_email(self):

        email = self.cleaned_data['email']

        try:
            validate_email( email )
        except ValidationError:
            raise forms.ValidationError(mark_safe('<div class="alert alert-danger">Digital Mail Address is invalid.</div>'))

        try:
            MemberUser.objects.get(email=email)
        except:
            return email

        raise forms.ValidationError(mark_safe('<div class="alert alert-danger">Digitial Mail Address is already registred.</div>'))



    def clean_password2(self):
      if 'password1' in self.cleaned_data:
        password1 = self.cleaned_data['password1']
        password2 = self.cleaned_data['password2']
        
        if password1 == password2:

            valid_password = True
            message = ''

            if len(password2) < 8:
                valid_password = False
                message += 'Password must be longer than 8 characters. '

            if not re.search(r'(?=.*[\d])',password2):
                valid_password = False
                message += 'Password did not contain one number. '

            if not re.search(r'(?=.*[a-z])',password2):
                valid_password = False
                message += 'Password did not contain a lower case character. '

            if not re.search(r'(?=.*[A-Z])',password2):
                valid_password = False
                message += 'Password did not contain a capital character. '

            if not re.search(r'(?=.*[\!\@\#\$\%\&\*\(\)\^\[\]\;\:\'\-\_\+\=\{\}\[\]\?\<\>\ \.\,\|\`\\\/]+.*)',password2):
                valid_password = False
                message += 'Password did not contain a special character. '

            if valid_password:
                return password2
            else:
                raise forms.ValidationError(mark_safe('<div class="alert alert-danger">'+message+'</div>'))

      raise forms.ValidationError(mark_safe('<div class="alert alert-danger">Passwords do not match.</div>'))


class LoginForm(forms.Form):
    class Meta:
       fields = '__all__' 
 
    email = forms.CharField(label='Email',widget=forms.TextInput(attrs={'size':'35'}),max_length=254)

    password = forms.CharField(
          label='Password',
          widget=forms.PasswordInput(attrs={'size':'35'}),
          max_length=254
    )

class MemberUserCreationForm(UserCreationForm):
    """
    A form that creates a user, with no privileges, from the given email and
    password.
    """

    def __init__(self, *args, **kargs):
        super(MemberUserCreationForm, self).__init__(*args, **kargs)
        del self.fields['username']

    class Meta:
        model = MemberUser
        fields = ("email","handle")

class MemberUserChangeForm(UserChangeForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """

    def __init__(self, *args, **kargs):
        super(MemberUserChangeForm, self).__init__(*args, **kargs)
        del self.fields['username']

    class Meta:
        model = MemberUser
        fields = '__all__' 
 



