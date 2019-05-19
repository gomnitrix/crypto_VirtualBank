import logging

from authenticate.models import Account
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from onlineBank.config import Config
from onlineBank.utils import creat_bill, get_account, get_user, get_userby_phone, if_login, md5, rsa_decrypt, set_salt, \
    verify_sign

from .models import Bills

logger = logging.getLogger('balance')


def manage(request, name):
    if not if_login(request, name):
        return redirect(reverse('signin'))
    user = get_user(name)
    account = get_account(name)
    outcome = account.cost
    balance = account.balance
    image = account.avatar
    outs_d = list(Bills.objects.values("amount").filter(payer_card=user.card))[-7:]
    incomes_d = list(Bills.objects.values("amount").filter(beneficiary=user.card))[-7:]
    outs = []
    incomes = []
    for i in range(len(outs_d)):
        outs.append(outs_d[i]["amount"])
    for i in range(len(incomes_d)):
        incomes.append(incomes_d[i]["amount"])
    outs += (7 - len(outs)) * [0]
    incomes += (7 - len(incomes)) * [0]
    month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul"]
    outs_dic = dict(zip(month, outs))
    incomes_dic = dict(zip(month, incomes))
    return render(request, "usersModule/manage.html",
                  {"name": name, "outcome": outcome, "income": balance, "image": image, "outs": outs_dic,
                   "incomes": incomes_dic})


def salt(request, name):
    salt = set_salt(request, name)
    return JsonResponse({"salt": salt})


def recharge(request, name):
    if not if_login(request, name):
        return redirect(reverse('signin'))
    user = get_user(name)
    account = get_account(name)
    card = user.card
    image = account.avatar
    if request.method == "POST":
        amount = request.POST.get("amount")
        passwd = request.POST.get("passwd")
        signature = request.POST.get("signature")
        salt = request.session[name]['salt']
        plaintext = rsa_decrypt([amount, passwd])
        success = ""
        money = float(plaintext[0])
        if money < 0:
            return JsonResponse({"message": "wrong amount"})
        if verify_sign([amount, passwd], signature, name):
            if md5(user.pay_passwd + salt) == plaintext[1]:
                if not creat_bill(name, "", money, "recharge"):
                    return JsonResponse({"message": "create bill wrong"})
                account.balance += money
                account.save()
                logger.info('user: '+name+' operation: '+'recharge amount: '+str(money)+'$')
                message = "Your account has been recharged " + plaintext[0] + " yuan, Coming back to the homepage"
                success = True
            else:
                message = "wrong password"
        else:
            message = "Signature verification failed"
        return JsonResponse({"message": message, "success": success})
    return render(request, "usersModule/Recharge.html", {"name": name, "card": card, "image": image})


def withdraw(request, name):
    if not if_login(request, name):
        return redirect(reverse('signin'))
    user = get_user(name)
    account = get_account(name)
    card = user.card
    image = account.avatar
    if request.method == "POST":
        amount = request.POST.get("amount")
        passwd = request.POST.get("passwd")
        signature = request.POST.get("signature")
        salt = request.session[name]['salt']
        plaintext = rsa_decrypt([amount, passwd])
        success = ""
        money = float(plaintext[0])
        if money < 0:
            return JsonResponse({"message": "wrong amount"})
        if verify_sign([amount, passwd], signature, name):
            if md5(user.pay_passwd + salt) == plaintext[1]:
                if account.balance < money:
                    message = " Insufficient account balance"
                    return JsonResponse({"message": message})
                if not creat_bill(name, "", money, "withdraw"):
                    return JsonResponse({"message": "create bill wrong"})
                account.balance -= money
                account.cost += money
                account.save()
                logger.info('user:%s operation:%s amount:%s $' % (name, 'withdraw', str(money)))
                message = "You have already withdraw " + plaintext[0] + " yuan, Coming back to the homepage"
                success = True
            else:
                message = "wrong password"
        else:
            message = "Signature verification failed"
        return JsonResponse({"message": message, "success": success})
    return render(request, "usersModule/Withdraw.html", {"name": name, "card": card, "image": image})


def transfer(request, name):
    if not if_login(request, name):
        return redirect(reverse('signin'))
    user = get_user(name)
    account = get_account(name)
    card = user.card
    image = get_account(name).avatar
    if request.method == "POST":
        amount = request.POST.get("amount")
        passwd = request.POST.get("passwd")
        b_phone = request.POST.get("b_phone")
        phone = request.POST.get("phone")
        salt = request.session[name]['salt']
        signature = request.POST.get("signature")
        ciphers = [amount, passwd, b_phone, phone]
        plaintext = rsa_decrypt(ciphers)
        success = ""
        try:
            beneficiary = Account.objects.get(user=plaintext[2])
        except:
            return JsonResponse({"message": "no such user"})
        if verify_sign(ciphers, signature, name):
            if md5(user.pay_passwd + salt) == plaintext[1]:
                money = float(plaintext[0])
                if money < 0:
                    return JsonResponse({"message": "wrong amount"})
                if account.balance < money:
                    return JsonResponse({"message": "Insufficient account balance"})
                if not creat_bill(name, get_userby_phone(beneficiary.user).card, money, "transfer"):
                    return JsonResponse({"message": "create bill wrong"})
                account.balance -= money
                account.cost += money
                account.save()
                beneficiary.balance += money
                beneficiary.save()
                logger.info('user:%s operation:%s amount:%s $ to beneficiary:%s' % (
                    name, 'transfer', str(money), beneficiary.name))
                message = "You have already transfer " + plaintext[0] + " yuan, Coming back to the homepage"
                success = True
            else:
                message = "wrong password"
        else:
            message = "Signature verification failed"
        return JsonResponse({"message": message, "success": success})
    return render(request, "usersModule/Transfer.html", {"name": name, "card": card, "image": image})


def bills(request, name):
    if not if_login(request, name):
        return redirect(reverse('signin'))
    user = get_user(name)
    account = get_account(name)
    image = account.avatar
    outs = list(Bills.objects.filter(payer_card=user.card))
    outs.reverse()
    incomes = list(Bills.objects.filter(beneficiary=user.card))
    incomes.reverse()
    return render(request, "usersModule/Bills.html",
                  {"name": name, "image": image, "outs": outs[0:Config.max_num], "incomes": incomes[0:Config.max_num]})


def info(request, name):
    if not if_login(request, name):
        return redirect(reverse('signin'))
    user = get_user(name)
    account = get_account(name)
    if request.method == "POST":
        file = request.FILES['avatar']
        if file:
            account.avatar = file
            account.save()
    card = user.card
    phone = user.phone
    time = account.regtime
    image = account.avatar
    return render(request, "usersModule/Info.html",
                  {"name": name, "card": card, "phone": phone, "time": time, "image": image})


def edit(request, name):
    if not if_login(request, name):
        return redirect(reverse('signin'))
    user = get_user(name)
    account = get_account(name)
    image = account.avatar
    if request.method == "POST":
        name = request.POST.get("name", None)
        ppasswd = request.POST.get("ppasswd", None)
        card = request.POST.get("card", None)
        phone = request.POST.get("phone", None)
        passwd = request.POST.get("passwd", None)
        opasswd = request.POST.get("opasswd", None)
        success = False
        if opasswd:
            opasswd = rsa_decrypt([opasswd])[0]
            if user.passwd == md5(opasswd):
                if name:
                    user.name = rsa_decrypt([name])[0]
                if ppasswd:
                    user.pay_passwd = md5(rsa_decrypt([ppasswd])[0])
                if card:
                    user.card = rsa_decrypt([card])[0]
                if phone:
                    phone = rsa_decrypt([phone])[0]
                    user.phone = phone
                    account.user = phone
                if passwd:
                    user.passwd = md5(rsa_decrypt([passwd])[0])
                user.save()
                account.save()
                message = "success"
                success = True
            else:
                message = "wrong password"
        else:
            message = "old password could not be empty"
        return JsonResponse({"message": message, "success": success})
    return render(request, "usersModule/Edit.html", {"name": name, "image": image})


def logout(request, name):
    user = request.session.get(name, None)
    if user:
        del request.session[name]
    return render(request, "authenticate/signin.html")
