import base64
import json
import urllib
from urllib import parse, request

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Sign_PKCS
from authenticate.models import Account, User

from onlineBank.onlineBank.config import Config
from .models import Bills


def if_login(request, name):
    user = request.session.get(name, None)
    if not (user and user.get('is_login', None)):
        return False
    return True


def sha_pre(ciphers):
    after = []
    for item in ciphers:
        data = parse.unquote(item)
        after.append(data)
    b = (''.join(s for s in after)).encode()
    return b


def verify_sign(ciphers, signature, name):
    data = sha_pre(ciphers)
    h = Crypto.Hash.SHA256.new(data)
    user = User.objects.get(name=name)
    pub_key = user.pub_key
    if not pub_key:
        pub_key = get_userpub(name)
        if not pub_key:
            return False
    user_pubkey = RSA.import_key(
        open(pub_key, "rb").read()
    )
    signature = base64.b64decode(parse.unquote(signature))
    return Sign_PKCS.new(user_pubkey).verify(h, signature)


def get_user(name):
    user = User.objects.get(name=name)
    return user


def get_account(name):
    user = get_user(name)
    return Account.objects.get(user=user.phone)


def get_userby_phone(phone):
    return User.objects.get(phone=phone)


def creat_bill(name, bene_card, amount, bill_type):
    try:
        user = get_user(name)
        if bill_type == "recharge":
            Bills.objects.create(payer=name, payer_card=name, beneficiary=user.card, amount=amount,
                                 bill_type=bill_type)
        elif bill_type == "withdraw":
            Bills.objects.create(payer=name, payer_card=user.card, beneficiary=name, amount=amount,
                                 bill_type=bill_type)
        else:
            Bills.objects.create(payer=name, payer_card=user.card, beneficiary=bene_card, amount=amount,
                                 bill_type=bill_type)
        return True
    except Exception as e:
        print(e)
        return False


def verify_casign(ciphers, signature):
    data = (''.join(s for s in ciphers)).encode()
    h = Crypto.Hash.SHA256.new(data)
    user_pubkey = RSA.import_key(
        open(get_user("CA").pub_key).read()
    )
    signature = base64.b64decode(signature)
    return Sign_PKCS.new(user_pubkey).verify(h, signature)


def get_userpub(name):
    headers = {
        'User-Agent': Config.User_Agent}
    post_data = urllib.parse.urlencode({
        "DN": name
    }).encode()
    ca_url = Config.CA_GetCert
    req = request.Request(url=ca_url, data=post_data, headers=headers)
    data = request.urlopen(req).read().decode()
    certinfo = json.loads(data)
    version = certinfo['version']
    publickey = certinfo['publickey']
    cert_seq = certinfo['cert_seq']
    DN = certinfo['DN']
    validData = certinfo['validData']
    ca = certinfo['ca']
    sign = certinfo['signature']
    if verify_casign([version, publickey, cert_seq, DN, validData, ca], sign):
        with open(
                Config.key_url + name + "_pub.pem",
                "wb+") as f:
            f.write(publickey)
        user = get_user(name)
        user.pub_key = name + "_pub.pem"
        user.save()
        return user.pub_key
    else:
        return False
