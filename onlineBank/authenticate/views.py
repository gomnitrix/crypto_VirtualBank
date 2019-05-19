import json
import os
import random
import urllib
import base64
from urllib import parse, request as urequest

from Crypto.PublicKey import RSA
from django.http import JsonResponse
from django.shortcuts import HttpResponse, redirect, render
from django.urls import reverse
from onlineBank.config import Config
from onlineBank.utils import aes_decrypt, aes_encrypt, creat_bill, get_account_by_card, get_rsa_pubkey, \
    get_user_by_card, md5, part_and_verify, post, rsa_decrypt, set_salt, sha256, verify_sign, get_paybill, get_account, \
    get_user

from .models import Account, User, PayBill


def register(request):
    return render(request, "authenticate/register.html")


def su_request(request):
    if request.method == "POST":
        signup = request.POST.get('signup_request')
        if signup == "true":
            if not os.path.exists(
                    Config.key_url + "rsa_private.bin"):
                key = RSA.generate(1024)
                encrypted_key = key.exportKey(passphrase="981017", pkcs=8,
                                              protection="scryptAndAES128-CBC")
                with open(
                        Config.key_url + "rsa_private.bin",
                        "wb+") as f:
                    f.write(encrypted_key)
                with open(
                        Config.key_url + "rsa_public.pem",
                        "wb+") as f:
                    f.write(key.publickey().exportKey())
            return JsonResponse({"pub_key": get_rsa_pubkey()})
        else:
            name = request.POST.get('name')
            phone = request.POST.get('phone')
            card = request.POST.get('card')
            id_no = request.POST.get('id_no')
            passwd = request.POST.get('passwd')
            cipher_data = [name, id_no, phone, card, passwd]
            plaintext = rsa_decrypt(cipher_data)
            User.objects.get_or_create(name=plaintext[0], id_no=plaintext[1], phone=plaintext[2], card=plaintext[3],
                                       passwd=md5(plaintext[4]), pay_passwd='12345678')
            Account.objects.get_or_create(user=plaintext[2], avatar="avatar/48.jpg", balance="0", cost="0")
            return JsonResponse({"saved": True})


def signin(request):
    if request.method == "POST":
        signin = request.POST.get("si_request")
        if signin == "true":
            [salt_id, salt] = set_salt(request)
            return JsonResponse({"pub_key": get_rsa_pubkey(), "salt": salt, "salt_id": salt_id})
        else:
            name = request.POST.get("name")
            passwd = request.POST.get("passwd")
            salt_id = request.POST.get("salt_id")
            if not name or not passwd:
                return JsonResponse({"message": "name or password could not be empty"})
            plaintext = rsa_decrypt([name, passwd])
            passwd = plaintext[1]
            try:
                passwd_of_models = User.objects.values("passwd").get(name=plaintext[0]).get("passwd")
                corr_pass = md5(passwd_of_models + request.session[salt_id])
                if passwd == corr_pass:
                    user = request.session.get(plaintext[0], None)
                    if user and user['is_login']:
                        message = "You are already logged in"
                        return JsonResponse({"message": message})
                    del request.session[salt_id]
                    request.session[plaintext[0]] = {'is_login': True, 'user_name': plaintext[0]}
                    request.session.set_expiry(0)
                    pay_passwd = User.objects.values("pay_passwd").get(name=plaintext[0]).get("pay_passwd")
                    if not pay_passwd or pay_passwd == '12345678':
                        url = reverse("set_paypasswd", kwargs={"name": plaintext[0]})
                        return JsonResponse({"if_success": True, "url": url})
                    return JsonResponse({"if_success": True, "url": reverse("manage", kwargs={"name": plaintext[0]})})
                else:
                    message = "wrong password"
            except User.DoesNotExist:
                message = " User does not exist"
        return JsonResponse({"message": message})
    else:
        return render(request, "authenticate/signin.html")


def prompt(request):
    return render(request, "authenticate/prompt.html")


def set_paypasswd(request, name):
    user = request.session.get(name, None)
    if not (user and user.get('is_login', None)):
        return render(request, "authenticate/signin.html")
    if request.method == 'POST':
        set_pay = request.POST.get('set')
        if set_pay == 'true':
            return JsonResponse({"pub_key": get_rsa_pubkey()})
        else:
            passwd = request.POST.get("passwd")
            if not passwd:
                return JsonResponse({"message": "password could not be empty"})
            pay_passwd = rsa_decrypt([passwd])[0]
            if pay_passwd == '12345678' or pay_passwd == '':
                return JsonResponse({"message": "pay password to simple", "url": ''})
            else:
                the_user = User.objects.get(name=name)
                the_user.pay_passwd = md5(pay_passwd)
                the_user.save()
                return JsonResponse(
                    {"message": "pay password has been saved", "url": reverse("manage", kwargs={"name": name})})
    return render(request, "authenticate/setpay.html")


def deal(request):
    if request.method == "POST":
        if request.POST.get("pay_request") != "true":
            amount_c = request.POST.get("amount")
            card_c = request.POST.get("card")
            cert = request.POST.get("certificate")
            sign = request.POST.get("signature")
            aes_key = request.POST.get("aes_key")
            deal_identify = request.POST.get("deal_identify")
            aes = rsa_decrypt([aes_key])
            [amount, card] = aes_decrypt([amount_c, card_c], aes)
            if not part_and_verify(cert) or not verify_sign([amount_c, card_c], sign, Config.Plat_name):
                return HttpResponse("Verification Failed")

            pay_id = random.randint(Config.min_payId, Config.max_payId)

            PayBill.objects.create(amount=amount, card=card, key=base64.b64encode(aes).decode(),
                                   deal_identify=deal_identify, pay_id=pay_id)
            return JsonResponse({"pay_id": str(pay_id)})
    return HttpResponse('NULL')


def pay_transfer(request, pay_id):
    if request.method != "POST":
        return HttpResponse("method should be POST")
    success = False
    info_dict = get_paybill(pay_id)
    aes_key = base64.b64decode(info_dict.key.encode())
    user_cert = json.loads(request.POST.get('cert'))
    hash_oi = request.POST.get('hashOI')
    sign = request.POST.get('sign')
    [hash_oi, sign] = aes_decrypt([hash_oi, sign], aes_key)
    hash_pi = info_dict.hash_pi
    if not part_and_verify(user_cert):
        message = "cert verify failed"
    elif not verify_sign([hash_pi, hash_oi], sign, user_cert['DN']):
        message = "signature verify failed"
    else:
        amount = info_dict.amount
        card = info_dict.card
        beneficiary = get_account_by_card(card)
        money = float(amount)
        user_name = info_dict.payer_name
        user = get_user(user_name)
        account = get_account(user_name)
        if account.balance < money:
            message = "Insufficient account balance"
        elif not creat_bill(user.name, card, money, "transfer"):
            message = "create bill wrong"
        else:
            if not creat_bill(user.name, card, money, "transfer"):
                return JsonResponse({"message": "create bill wrong"})
            account.balance -= money
            account.cost += money
            account.save()
            beneficiary.balance += money
            beneficiary.save()
            message = "You have already pay " + amount + " yuan"
            success = True
    return HttpResponse("success" if success else message)


def pay(request, pay_id):
    info_dict = get_paybill(pay_id)
    if request.method == "POST":
        flag=False
        phone = request.POST.get("phone")
        passwd = request.POST.get("passwd")
        pay_id = request.POST.get("pay_id")
        [phone, passwd, pay_id] = rsa_decrypt([phone, passwd, pay_id])
        try:
            user = User.objects.get(phone=phone)
        except:
            return JsonResponse({"message": "no such user"})
        if md5(passwd) == user.pay_passwd:
            pi = [user.name, user.phone, user.card]
            deal_identify = info_dict.deal_identify
            aes_key = base64.b64decode(info_dict.key.encode())
            hash_pi = sha256(pi)
            info_dict.payer_name = user.name
            info_dict.hash_pi = hash_pi
            info_dict.save()
            hash_pi_c = aes_encrypt(hash_pi, aes_key)
            deal_identify = aes_encrypt(deal_identify, aes_key)

            '''发送hash_pi和订单号'''
            data = post(Config.Plat_PayHost, {"hashPI": hash_pi_c, "deal_identify": deal_identify})
            data = json.loads(data)  # 不确定的类型，debug
            flag = data['flag']
            message = "succeed,Jumping to the CA Certification Center"
        else:
            message = "wrong password"
        return JsonResponse({"message": message + ",Transaction closed", "flag": flag})
    card = info_dict.card
    amount = info_dict.amount
    user = get_user_by_card(card)
    name = user.name
    account = get_account_by_card(card)
    avatar = account.avatar
    return render(request, "authenticate/pay.html", {"amount": amount, "name": name, "image": avatar, "id": pay_id})


def key(request, name):
    user = request.session.get(name, None)
    if not (user and user.get('is_login', None)):
        return render(request, "authenticate/signin.html")
    if request.method == "POST":
        post_data = {
            "key": parse.unquote(request.POST.get("key")),
            "email": parse.unquote(request.POST.get("email")),
            "passwd": parse.unquote(request.POST.get("passwd"))
        }
        ca_url = Config.CA_requir
        headers = {
            'User-Agent': Config.User_Agent}
        post_data = urllib.parse.urlencode(post_data).encode()
        req = urequest.Request(url=ca_url, data=post_data, headers=headers)
        data = urequest.urlopen(req).read().decode()
        return JsonResponse({"privatekey": data})
    return render(request, "authenticate/key.html", {"name": name})
