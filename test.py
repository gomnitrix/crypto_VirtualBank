import json
import urllib
from urllib import parse, request
from base64 import b64decode

import Crypto
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA


def verify(sign, message):
    digest = Crypto.Hash.SHA256.new()
    digest.update(message)
    # 从文件中读出公钥
    pubk_file = open("C:\\Users\omnitrix\PycharmProjects\\virtualBank\onlineBank\\authenticate\\rsa\\ca_pub.pem", "r")
    pubk = RSA.importKey(pubk_file.read())
    # 对hash进行验证
    verifer = PKCS1_v1_5.new(pubk)
    is_verify = verifer.verify(digest, sign)

    if is_verify == 0:
        print("验证失败")
    return is_verify


'''if __name__ == '__main__':
    sign = b64decode(
        "tmHYsP+h0n6SQJ1RlltsITGLmt35gvbj4WTrye//mwODwQNuqZCAnXQmfjVPiMKcZKvvuoBisW5OwUIlOHUMkogtCGzx7V+tERK7K0CUVikXsKAelrlwDgksqwCCFHdkjCDj18XH9IvbhzGRYXX6Z8SGWXujTgjv+OirCRmqPX0=".encode())
    # message = "3"+""+""+""+""+""+""
    # print(message)
    print(sign)
    message = (
                "3" + "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCckE3xJP76k7Lmi42oOSfkuXDB\nBepcMqdZfXC5EQYOxHRKkTxywFwjPlq1zRYkpq5vQzAhl8tQaBTgw0pqQtbnEWhV\nW6CdnF7gbaAnvqEKRkG1cU68Fjo0+G4enW4TdUU6eK58FrmboY/RgsO6jjrT+RyG\nrqfkOUbM7flQ8vDF9wIDAQAB\n-----END PUBLIC KEY-----" + "7" + "pys" + "2019-01-18" + "ljw").encode()
    print(message)
    print(verify(sign, message))'''


def get_cert():
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36 LBBROWSER'}
    publickey = open("C:\\Users\omnitrix\PycharmProjects\\virtualBank\onlineBank\\authenticate\\rsa\\rsa_public.pem",
                     "r").read()
    post_data = urllib.parse.urlencode({
        "DN": "Virtual Bank",
        "publickey": publickey
    }).encode()
    ca_url = "http://192.168.43.59:8000/ca/trader_register/"
    req = request.Request(url=ca_url, data=post_data, headers=headers)
    data = request.urlopen(req).read().decode()
    print(data)
get_cert()