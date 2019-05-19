from django.db import models


# Create your models here.

class Bills(models.Model):
    payer = models.CharField(max_length=10)
    payer_card = models.CharField(max_length=20)
    beneficiary = models.CharField(max_length=20)
    amount = models.FloatField()
    bill_type = models.CharField(max_length=8)
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return 'payer:' + str(self.payer) + 'beneficiary:' + str(self.beneficiary)
