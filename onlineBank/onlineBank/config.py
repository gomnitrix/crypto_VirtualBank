class Config:
    CA_Host = "http://192.168.43.59:8000/"  # Ca certification center host
    CA_GetCert = CA_Host+"ca/require/"  # certification require host
    CA_requir = CA_Host+"ca/Require_prik/"
    CA_register = CA_Host+"ca/trader_register/"

    Plat_Host = "http://192.168.43.160:8000/"  # E-commerce platform host
    Plat_PayHost = Plat_Host+"bank_receipt/pi"
    Plat_name = "SunShine Bookstore"  # E-commerce platform's name in CA

    User_Agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 ' \
                 '(KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36 LBBROWSER'  # Post headers

    key_url = "C:\\Users\omnitrix\PycharmProjects\\virtualBank\onlineBank\\authenticate\\rsa\\"
    # rsa private keys and public keys URL

    max_num = 10  # Bills page max num

    max_saltId = 20  # max number of random salt id
    salt_Length = 8  # salt length

    max_payId = 10000
    min_payId = 0

    Base_DIR = "C:\\Users\omnitrix\PycharmProjects\\virtualBank\onlineBank\\onlineBank\\log"
