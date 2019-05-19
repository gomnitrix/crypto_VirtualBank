from django.db import models


class User(models.Model):
    name = models.CharField(max_length=25)
    id_no = models.CharField(max_length=18)
    card = models.CharField(max_length=20)
    phone = models.CharField(max_length=11)
    passwd = models.CharField(max_length=50)
    pay_passwd = models.CharField(max_length=50)
    pub_key = models.FilePathField(
        path="C:\\Users\omnitrix\PycharmProjects\\virtualBank\onlineBank\\authenticate\\rsa\\", blank=True, null=True)

    def __str__(self):
        return str(self.name) + ', phone:' + str(self.phone)


class Account(models.Model):
    user = models.CharField(max_length=11)
    avatar = models.ImageField(upload_to='avatar')
    balance = models.FloatField()
    cost = models.FloatField()
    regtime = models.DateField(auto_now_add=True)

    def __str__(self):
        return str(self.user) + ', balance:' + str(self.balance)


class PayBill(models.Model):
    amount = models.CharField(max_length=10)
    card = models.CharField(max_length=20)
    key = models.CharField(max_length=100)
    deal_identify = models.CharField(max_length=10)
    pay_id = models.CharField(max_length=5)
    hash_pi = models.CharField(max_length=100, blank=True, null=True)
    payer_name = models.CharField(max_length=25, blank=True, null=True)
