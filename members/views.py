# Create your views here./
from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib.auth import authenticate, login as auth_login
from django.template import Context, loader
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth.models import User, Permission
from members.forms import *
from members.models import *
from datetime import datetime  
from django.shortcuts import redirect
from decimal import *

import time
import hmac
import hashlib
import base64

ctf_name = 'Capture The Flag Sausage Land Edition'
url = settings.URL

game_off = False
game_start = 1468432800
game_end   = 1469836800

def validateEmail( email ):
    from django.core.validators import validate_email
    from django.core.exceptions import ValidationError
    try:
        validate_email( email )
        return True
    except ValidationError:
        return False

def index(request):
	

    if request.user.is_authenticated():
        request.session.modified = True

        completed_captures  = Capture.objects.filter(user = request.user,valid=True)
        rejected_captures   = Capture.objects.filter(user = request.user,valid=False)
        deltacredits_sums   = Decimal(0.00)

        for capture in completed_captures:
            deltacredits_sums = deltacredits_sums + capture.contract.payment

        page_data = {
                        'user'               : request.user,
                        'message'            : ctf_name,
                        'completed_captures' : completed_captures,
                        'rejected_captures'  : rejected_captures,
                        'deltacredit_total'  : deltacredits_sums,
			'game_over'          : game_off,
                    }

        variables = RequestContext(request,page_data)
        return render_to_response('members/index.html', variables)

    page_data = {'game_over'  : game_off
		 ,'game_start': game_start	
		 ,'game_end' : game_end	
		,'current_time':time.time()}
    variables = RequestContext(request,page_data)
    return render_to_response('members/index.html', RequestContext(request,variables))

def newsfeed(request):

	if not game_off:
    
		newsfeed = NewsFeed.objects.order_by("-publish_date")[:10]

		page_data = {
				'user'      : request.user,
				'newsfeed'  : newsfeed,
				'game_over' : game_off,
			    }


		variables = RequestContext(request,page_data)

		return render_to_response('members/newsfeed.html', variables)
	else:
		newsfeed = NewsFeed.objects.order_by("-publish_date")[:10]
		
		message = ''		

		page_data = {
				'message'   : message,
				'user'      : request.user,
				'newsfeed'  : newsfeed,
				'game_over' : game_off,
			    }


		variables = RequestContext(request,page_data)

		return render_to_response('members/newsfeed.html', variables)
	



def topagents(request):

	users = Capture.objects.raw('Select * from members_memberuser where is_superuser = 0')

	user_scores = []
	for user in users:

	    score = Decimal(0.00)
	    completed_captures = Capture.objects.filter(user__id__exact=user.id,valid=True)

	    for capture in completed_captures:
		score = score + capture.contract.payment

	    user_scores.append( {'handle': user.handle , 'score': score,'completed':len(completed_captures)})

	agent_list = sorted(user_scores,key=lambda k: k['score'])
	page_data = {
			'user'          : request.user,
			'agent_scores'  : reversed(agent_list),
			'game_over'     : game_off,
		    }

	variables = RequestContext(request,page_data)

	return render_to_response('members/topagents.html', variables)


def contract(request,contract_id):

    page_data = {}
    contract = None
    try:
        contract           = Contract.objects.get(pk=contract_id)
    except Exception,ex:
        contract = None

    if contract is None:
  	page_data = {'game_over' : game_off}
    	variables = RequestContext(request,page_data)
    	return render_to_response('members/index.html', RequestContext(request,variables))

    if request.user.is_authenticated():

        info = None

        contract_categories         = ContractCategory.objects.all()
        request.session.modified    = True

        completed_capture = None
        pre_capture       = Capture.objects.filter(user = request.user,valid=True,contract=contract)

        if len(pre_capture) > 0:
            completed_capture = pre_capture[0]

        if game_off:

            info = {}
            info['valid']   = False
            info['message'] = 'Sorry the game is over!'
                   
            page_data = {
                        'user'              :   request.user,
                        'message'           :   ctf_name,
                        'contract'          :   contract,
                        'categories'        :   contract_categories,
                        'url'               :   url,
                        'info'              :   info,
                        'completed_capture' :   completed_capture,
			'game_over'         :   game_off,
                        }

            #disable contract submit
            variables = RequestContext(request,page_data)
            return render_to_response('members/contract.html', variables)

        if request.method == 'POST':

            if completed_capture is not None:

                page_data = {
                        'user'              :   request.user,
                        'message'           :   ctf_name,
                        'contract'          :   contract,
                        'categories'        :   contract_categories,
                        'url'               :   url,
                        'info'              :   info,
                        'completed_capture' :   completed_capture,
			'game_over' 	    :   game_off,

                        }

                variables = RequestContext(request,page_data)
                return render_to_response('members/contract.html', variables)






            if 'contract_capture' in  request.POST:
                contract_capture = request.POST['contract_capture']
                capture = Capture(  contract        = contract, 
                                    capture_date    = timezone.now(),
                                    user            = request.user,
                                    evidence        = contract_capture 
                                    )


                capture.evidence_prehash    = capture.calcprehash(contract_capture)
                capture.evidence_hash       = capture.calchash(capture.evidence_prehash)
                capture_hash = capture.evidence_hash

                if capture_hash == contract.flag_hash:
                    info = {}
                    capture.valid   = True
                    info['valid']   = True
                    info['message'] = 'You have successfully submited this contract.'
                    capture.save()
                    completed_capture   = capture
                else:
                    info = {}
                    info['valid']   = False
                    info['message'] = 'Sorry your submission failed for  this contract.'
                    capture.valid   = False
                    capture.save()


                page_data = {
                        'user'              :   request.user,
                        'message'           :   ctf_name,
                        'contract'          :   contract,
                        'categories'        :   contract_categories,
                        'url'               :   url,
                        'info'              :   info,
                        'completed_capture' :   completed_capture,
			'game_over'         :   game_off,
                        }



            else:
                page_data = {
                        'user'          :   request.user,
                        'message'       :   ctf_name,
                        'contract'      :   contract,
                        'categories'    :   contract_categories,
                        'url'           :   url,
                        'info'          :   info,
                        'completed_capture' :  completed_capture,
			'game_over'         :  game_off,

                        }

        else:
            page_data = {
                        'user'          :   request.user,
                        'message'       :   ctf_name,
                        'contract'      :   contract,
                        'categories'    :   contract_categories,
                        'url'           :   url,
                        'info'          :   info,
                        'completed_capture' :  completed_capture,
			'game_over'         :  game_off,

                        }

        variables = RequestContext(request,page_data)
        return render_to_response('members/contract.html', variables)

    page_data = {'game_over' : game_off}
    variables = RequestContext(request,page_data)
    return render_to_response('members/index.html', RequestContext(request,variables))

def all_contract_categories(request):
    return contract_categories(request,None)

def contract_categories(request,category_id):

    if request.user.is_authenticated():
        contract_categories         = ContractCategory.objects.all()
        request.session.modified    = True

        if category_id is not None:
            try:
                selected_category   = ContractCategory.objects.get(pk=category_id)
                contracts           = Contract.objects.filter(category=category_id)
            except:
                selected_category   = None
                contracts           = Contract.objects.all()

        else:
            selected_category   = None
            contracts           = Contract.objects.all()
            

        page_data = {
                    'user'                  :   request.user,
                    'message'               :   ctf_name,
                    'contracts'             :   contracts,
                    'categories'            :   contract_categories,
                    'selected_category'     :   selected_category,
		    'game_over'             :   game_off,
                    }

        variables = RequestContext(request,page_data)

        return render_to_response('members/category.html', variables)

    page_data = {'game_over' : game_off}
    variables = RequestContext(request,page_data)
    return render_to_response('members/index.html', RequestContext(request,variables))


def login(request):

    if game_off:
    	page_data = {'game_over' : game_off}
    	variables = RequestContext(request,page_data)
    	return render_to_response('members/index.html', RequestContext(request,variables))

   # if game_start > time.time():
   # 	page_data = { 'game_start' : game_start,
   #     	      'game_end' : game_end,
   #     	      'current_time' : time.time(),
   #     	      'message' : 'Sorry you cannot login until the game starts.',
   #     	    }

   # 	variables = RequestContext(request,page_data)
   # 	return render_to_response('members/index.html', RequestContext(request,variables))


    if request.method == 'POST':
        request.session.modified = True    
        form = LoginForm(request.POST)
        if not form.is_valid():
            message = "Registration failed please try again."
            form = LoginForm()
            variables = RequestContext(request, {'form': form,'message':message})
            return render_to_response('registration/login.html',variables)


        u_email     = request.POST['email']
        u_password  = request.POST['password']

        if validateEmail(u_email):
            try:
                user = MemberUser.objects.get(email=u_email)
            except MemberUser.DoesNotExist:
                 message = "Your digital media address (email) or password is incorrect."
                 form = LoginForm()
                 variables = RequestContext(request, {'form': form,'message':message})
                 return render_to_response('registration/login.html',variables)
        else:
            message = "Your digital media address (email) or password is incorrect."
            form = LoginForm()
            variables = RequestContext(request, {'form': form,'message':message})
            return render_to_response('registration/login.html',variables)

        if user.is_active:
            user = authenticate(username=u_email, password=u_password)
            if user is not None:
                if user.check_password(u_password):
                     auth_login(request,user)
                     return redirect('/')
                else:
                     message = "Your digital meedia address or password is incorrect."
                     form = LoginForm()
                     variables = RequestContext(request, {'form': form,'message':message})
                     return render_to_response('registration/login.html',variables)
            else:
                message = "Your username or password is incorrect."
                form = LoginForm()
                variables = RequestContext(request, {'form': form,'message':message})
                return render_to_response('registration/login.html',variables)

    else:
        request.session.modified = True
        form = LoginForm()
        variables = RequestContext(request, {'form': form})
        return render_to_response('registration/login.html',variables)


def register_success(request):
    return render_to_response('registration/register_success.html', RequestContext(request))

def logout_page(request):
    logout(request)
    return HttpResponseRedirect('/')


def register_page(request):


    if request.user.is_authenticated() or game_off:
       page_data = {'game_over' : game_off}
       variables = RequestContext(request,page_data)
       return render_to_response('members/index.html', RequestContext(request,variables))


    if request.method == 'POST':
       form = RegistrationForm(request.POST)

       if form.is_valid():
            user = MemberUser.objects.create_user(
                     email         =    form.cleaned_data['email'],
                     password      =    form.cleaned_data['password1'],
                     handle        =    form.cleaned_data['handle'],
                     first_name    =    form.cleaned_data['first_name'],
                     last_name     =    form.cleaned_data['last_name'],
                     phone_number  =    '',
                     secret_phrase =    form.cleaned_data['secret_phrase'],
               )

            return HttpResponseRedirect('/agents/register/success/')

       else:

           variables = RequestContext(request, {
           'form': form
           })
           return render_to_response('registration/register.html', variables)
    else:
       form = RegistrationForm()
       
       variables = RequestContext(request, {
       'form': form
       })
       return render_to_response('registration/register.html', variables)


