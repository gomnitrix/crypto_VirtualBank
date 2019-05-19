import base64
import hashlib
import json
import random
import urllib
from random import Random
from urllib import parse, parse, request

import Crypto
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Sign_PKCS
from Crypto.Util.Padding import pad, unpad
from authenticate.models import Account, User, PayBill
from usersModule.models import Bills

from .config import Config


def rsa_decrypt(ciphers):
    plaintext = []
    private_key = RSA.import_key(
        open(Config.key_url + "rsa_private.bin",
             "rb").read(),
        passphrase='981017'
    )
    cipher_rsa = PKCS1_v1_5.new(private_key)
    for cipher in ciphers:
        data = parse.unquote(cipher)
        data = base64.b64decode(data)
        data = cipher_rsa.decrypt(data, None)
        try:
            plaintext.append(data.decode())
        except (AttributeError, UnicodeDecodeError):
            return data
    return plaintext


def aes_decrypt(ciphers, key):
    plaintext = []
    for cipher in ciphers:
        aes = AES.new(key, AES.MODE_CBC, key)
        cipher = base64.b64decode(parse.unquote(cipher))
        cipher = unpad(aes.decrypt(cipher), AES.block_size)
        try:
            plaintext.append(cipher.decode())
        except UnicodeDecodeError:
            plaintext.append(cipher)
    return plaintext


def aes_encrypt(plaintext, key):
    plaintext = plaintext.encode()
    key = AES.new(key, AES.MODE_CBC, key)
    ct_bytes = key.encrypt(pad(plaintext, AES.block_size))
    ct = base64.b64encode(ct_bytes)
    ct = ct.decode('utf-8')
    return ct


def md5(text):
    if type(text) == str:
        text = text.encode()
    return hashlib.md5(text).hexdigest()


def get_rsa_pubkey():
    pub_key = open(
        Config.key_url + "rsa_public.pem",
        "rb").read().decode()
    return pub_key


def get_salt(length=4):
    salt = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    len_chars = len(chars) - 1
    random = Random()
    for i in range(length):
        salt += chars[random.randint(0, len_chars)]
    return salt


def set_salt(request, name=None):
    salt = get_salt(Config.salt_Length)
    if not name:
        salt_id = random.randint(0, Config.max_saltId)
        request.session[salt_id] = salt
    else:
        tmp = request.session[name]
        tmp['salt'] = salt
        request.session[name] = tmp
        return salt
    return [salt_id, salt]


def get_account_by_card(card):
    user = User.objects.get(card=card)
    account = Account.objects.get(user=user.phone)
    return account


def get_user_by_card(card):
    user = User.objects.get(card=card)
    return user


def sha256(texts):
    sha = hashlib.sha256()
    for tex in texts:
        if type(tex) == str:
            tex = tex.encode()
        sha.update(tex)
    return sha.hexdigest()


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
    b = (''.join(after))
    b = b.encode()
    return b


def verify_sign(ciphers, signature, name):
    data = sha_pre(ciphers)
    h = Crypto.Hash.SHA256.new()
    h.update(data)
    user = User.objects.get(name=name)
    pub_key = user.pub_key
    if not pub_key:
        pub_key = get_userpub(name)
        if not pub_key:
            return False
    user_pubkey = RSA.import_key(
        open(pub_key, "r").read()
    )
    signature = base64.b64decode(sha_pre(signature))
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


def verify_certsign(ciphers, signature):
    data = sha_pre(ciphers)
    signature = sha_pre([signature])
    sha = Crypto.Hash.SHA256.new()
    sha.update(data)
    path = get_user("CA").pub_key
    pub = open(path, "r").read()
    pubkey = RSA.import_key(
        pub
    )
    signature = base64.b64decode(signature)
    return Sign_PKCS.new(pubkey).verify(sha, signature)


def part_cert(cert):
    infos = []
    for i in ['version', 'publickey', 'cert_seq', 'DN', 'validData', 'ca']:
        infos.append(cert[i])
    return infos


def part_and_verify(cert):
    if type(cert) == str:
        cert = json.loads(cert)
    infos = part_cert(cert)
    return verify_certsign(infos, cert['signature'])


def post(url, post_data):
    headers = {
        'User-Agent': Config.User_Agent}
    post_data = urllib.parse.urlencode(post_data).encode()
    req = request.Request(url=url, data=post_data, headers=headers)
    data = request.urlopen(req).read().decode()
    return data


def get_userpub(name):
    post_data = {
        "DN": name
    }
    ca_url = Config.CA_GetCert
    data = post(ca_url, post_data)
    certinfo = json.loads(data)['certInfo']
    if part_and_verify(certinfo):
        with open(
                Config.key_url + name + "_pub.pem",
                "w+") as f:
            f.write(certinfo['publickey'])
        user = get_user(name)
        user.pub_key = Config.key_url + name + "_pub.pem"
        user.save()
        return user.pub_key
    else:
        return False


def get_paybill(pay_id):
    return PayBill.objects.get(pay_id=pay_id)
