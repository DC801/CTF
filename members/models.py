from django.db import models
import time
import random
import string
import hmac
import hashlib
import base64
from django.utils import timezone
from django.utils.http import urlquote
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import (AbstractBaseUser, PermissionsMixin,UserManager)
from django.core.mail import send_mail
from django.core import validators
from django.contrib.auth.models import BaseUserManager
from django.conf import settings
from django.db.models.signals import pre_save
from django.dispatch import receiver
from twython import Twython, TwythonError

class MemberUserManager(BaseUserManager):

    def _create_user(self, email,handle, password,is_superuser,first_name,last_name,phone_number,secret_phrase):
        """
        Creates and saves a User with the given email and password.
        """

        now = timezone.now()
        if not email:
            raise ValueError('The given email must be set')
        confirmation_code = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for x in range(33))

        email = self.normalize_email(email)
        user = self.model(email=email,
                        handle=handle,
                        is_active=True,
                        is_superuser=is_superuser, 
                        last_login=now,
                        date_joined=now,
                        first_name=first_name,
                        last_name=last_name,
                        phone_number=phone_number,
                        confirmation_code=confirmation_code,
                        secret_phrase=secret_phrase,
                        )
        user.set_password(password)
        user.save(using=self._db)
        self.send_registration_confirmation(handle,email,confirmation_code)
        return user

    def create_user(self, email, handle, password=None, first_name=None, last_name=None, phone_number=None,secret_phrase=None):
        return self._create_user(email,handle,password, False,first_name,last_name,phone_number,secret_phrase)

    def create_superuser(self, email, handle, password, first_name=None, last_name=None, phone_number=None,secret_phrase=None):
        return self._create_user(email,handle, password, True, first_name, last_name,phone_number,secret_phrase)

    def send_registration_confirmation(self,handle,email,confirmation_code):

        title = "Eggplant is Online Confirmation"
        content = "https://ctf.eggplant.online/" + str(confirmation_code) + "/" + handle
        try:
            #send_mail(title, content, 'no-reply@dc801.org', [email], fail_silently=False)
            #forget email registration for now.
            pass
        except Exception,ex:
            f = open('/tmp/sendmail','w')
            f.write(repr(ex))
            f.close()

class MemberUser(AbstractBaseUser,PermissionsMixin):

    id               = models.AutoField(primary_key=True)
    email            = models.CharField(max_length=254, unique=True, db_index=True)
    handle           = models.CharField(max_length=254, unique=True)
    is_active        = models.BooleanField(_('active'), default=True,
                                            help_text=_('Designates whether this user should be treated as '
                                             'active. Unselect this instead of deleting accounts.'))
    
    date_joined       = models.DateTimeField(_('date joined'), default=timezone.now)
    objects           = MemberUserManager()
    first_name        = models.CharField(max_length=254, blank=True)
    last_name         = models.CharField(max_length=254, blank=True)
    phone_number      = models.CharField(max_length=11, blank=True)
    confirmation_code = models.CharField(max_length=33)
    secret_phrase     = models.CharField(max_length=254)

    USERNAME_FIELD   = 'email'
    REQUIRED_FIELDS = ['handle','first_name','last_name','phone_number','secret_phrase']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def __unicode__(self):  # Python 3: def __str__(self):
        return  str(self.handle)

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_superuser

    def get_absolute_url(self):
        return "/users/%s/" % urlquote(self.email)

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])


class CTFGame(models.Model):

    name        = models.CharField(max_length=254)
    start_time  = models.DateTimeField('Date Game Starts')
    end_time    = models.DateTimeField('Date Game Ends')
    description = models.CharField(max_length=254)

    def __unicode__(self):
        return self.name

class NewsFeed(models.Model):
    game_id         = models.ForeignKey(CTFGame)
    info            = models.CharField(max_length=254)
    publish_date    = models.DateTimeField()
    info_type       = models.IntegerField()

    def __unicode__(self):
        return self.info


class ContractCategory(models.Model):
    name    = models.CharField(max_length=254)
    game_id = models.ForeignKey(CTFGame)

    def __unicode__(self):
        return self.name

class ChallengeLevel(models.Model):
    name    = models.CharField(max_length=254)
    def __unicode__(self):
        return self.name

class FlagHandler(models.Model):

    class Meta:
        abstract = True

    def calcprehash(self,message):
        #remove all none printable chars
        #should make submiting flags easier
        pre_hash = ''.join(n for n in message if ord(n) >= 32 and ord(n) <= 126)
        pre_hash = pre_hash.replace(" ", "")
        pre_hash = pre_hash.lower()
        return pre_hash

    def calchash(self,message):
        dig = hmac.new(b'6789023123', msg=message, digestmod=hashlib.sha256).hexdigest()
        return dig



class Contract(FlagHandler):

    title           = models.CharField(max_length=254)
    category        = models.ForeignKey(ContractCategory) 
    file            = models.CharField(max_length=254,blank=True)
    handler         = models.ForeignKey(MemberUser)
    
    description     = models.CharField(max_length=254)
    breifing        = models.TextField()
    game_id         = models.ForeignKey(CTFGame)
    flag_answer     = models.CharField(max_length=254)
    flag_prehash    = models.CharField(max_length=254,blank=True)
    flag_hash       = models.CharField(max_length=254,blank=True)
    payment         = models.DecimalField(max_digits=8, decimal_places=2)
    challenge_level = models.ForeignKey(ChallengeLevel)

    def __unicode__(self):
        return self.title


    
class Capture(FlagHandler):

    contract            = models.ForeignKey(Contract)
    capture_date        = models.DateTimeField('Date flags was captured.')
    user                = models.ForeignKey(MemberUser)
    valid               = models.BooleanField()
    evidence_prehash    = models.CharField(max_length=254,blank=True)
    evidence_hash       = models.CharField(max_length=254,blank=True)
    evidence            = models.TextField()

    def __unicode__(self):
        return self.contract.title + ' Agent: ' +self.user.handle + ' Valid: ' +str(self.valid)




@receiver(pre_save, sender=Contract)
def contract_handler(sender, instance, *args, **kwargs):
    instance.flag_prehash = instance.calcprehash(instance.flag_answer)
    instance.flag_hash    = instance.calchash(instance.flag_prehash)

    if instance.pk is None:
        APP_KEY 	= 'mQWkHuWoA7w58t2w4tKFoML6T'
        APP_SECRET 	= 'FxVt29vqu8OdYF1eHCxlvWQCRiZfJF4Sq9P4hxeRSAXohiXtzp'
        OAUTH_TOKEN 	= '2157496260-Wbmox8obTRSN366EwH9LrFQNNja8JqNdF5J1jyD'
        OAUTH_TOKEN_SECRET = 'nJ2sZ1YcMuca00hgqVjZl6Dopg3fkk6JsENs70EOTi4QD'
        
        # Requires Authentication as of Twitter API v1.1
        twitter = Twython(APP_KEY, APP_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET)
        
        try:
            twitter.update_status(status='New Contract - '+ instance.title)
        except TwythonError as e:
            f = open('/tmp/twitter_errors','a')
            f.write(repr(e))
            f.close()
 

@receiver(pre_save,sender=NewsFeed)
def newsfeed_handler(sender, instance, *args, **kwargs):
    if instance.pk is None:
        APP_KEY 	= 'mQWkHuWoA7w58t2w4tKFoML6T'
        APP_SECRET 	= 'FxVt29vqu8OdYF1eHCxlvWQCRiZfJF4Sq9P4hxeRSAXohiXtzp'
        OAUTH_TOKEN 	= '2157496260-Wbmox8obTRSN366EwH9LrFQNNja8JqNdF5J1jyD'
        OAUTH_TOKEN_SECRET = 'nJ2sZ1YcMuca00hgqVjZl6Dopg3fkk6JsENs70EOTi4QD'
        
        # Requires Authentication as of Twitter API v1.1
        twitter = Twython(APP_KEY, APP_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET)
        
        try:
            twitter.update_status(status=instance.info)
        except TwythonError as e:
            f = open('/tmp/twitter_errors','a')
            f.write(repr(e))
            f.close()
    
