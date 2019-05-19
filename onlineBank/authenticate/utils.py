import base64
import hashlib
import random
from random import Random
from urllib import parse

from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from usersModule.config import Config

from .models import Account, User


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
        plaintext.append(cipher_rsa.decrypt(data, None).decode())
    return plaintext


def des_decrypt(ciphers, key):
    plaintext = []
    key = DES.new(key, DES.MODE_ECB)
    for cipher in ciphers:
        plaintext.append(key.decrypt(cipher))
    return plaintext


def md5(text):
    if type(text) == str:
        text = text.encode()
    return hashlib.md5(text).hexdigest()


def get_rsa_pubkey():
    pub_key = open(
        "C:\\Users\omnitrix\PycharmProjects\\virtualBank\onlineBank\\authenticate\\rsa\\rsa_public.pem",
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
    for text in texts:
        if type(text)==str:
            text=text.encode()
        sha.update(text)
    return sha.hexdigest()
