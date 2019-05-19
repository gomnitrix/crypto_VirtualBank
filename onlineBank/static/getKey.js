function get_private() {
    var key = localStorage.getItem(window.name);
    var pri_encrypt = new JSEncrypt();
    pri_encrypt.setPrivateKey(key);
    return pri_encrypt;
}

function get_serverPub() {
    var post_data = {
        'signup_request': true,
    };
    var pub_key;
    var pub_encrypt
    $.ajaxSettings.async = false;
    $.post(
        post_host,
        post_data,
        function (data, status) {
            pub_key = data.pub_key;
            pub_encrypt = new JSEncrypt();
            pub_encrypt.setPublicKey(pub_key);
        });
    $.ajaxSettings.async = true;
    return pub_encrypt;
}

function randomWord(len) {
    var str = "",
        range = len,
        arr = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];
    for (var i = 0; i < range; i++) {
        pos = Math.round(Math.random() * (arr.length - 1));
        str += arr[pos];
    }
    return str;
}

function encrypt(msg, key) {
    var a = CryptoJS.AES.encrypt(msg, key, {
        iv: key,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    }).ciphertext;
    a = CryptoJS.enc.Base64.stringify(a);
    a = a.toString();
    return a;
}
function decrypt(cipherText, key) {
    cipherText=atob(cipherText)
    var cipherText = CryptoJS.enc.Latin1.parse(cipherText);
    console.log(cipherText);
    var a=CryptoJS.AES.decrypt({ ciphertext: cipherText }, key, {
        iv: key,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    });
    a = CryptoJS.enc.Latin1.stringify(a);
    //a=a.toString(CryptoJS.enc.Utf8)
    //a=a.toString();
    console.log(a);
    return a;
}
function get_privateByCA() {
    var Ca_Host = "http://192.168.43.59:8000/ca/Require_prik/";
    var Ca_Pub = "-----BEGIN PUBLIC KEY-----"
        + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD5aVOI1zd2TyQVRHwghq0VLgmR"
        + "bKyKJtHw9KzIrRh2v9q1MXeZnZlfOpb3VOE0cKubfxWX8w6UNmAYcNDIHXO0UVjN"
        + "m6KIvM5xUGvmfcL4oCR+CoFl1Lr29oIGseiCPjsk4Epqr3WTNTMRcO+brSD0uMN6"
        + "HpodKKXFO1HWU/6ZzQIDAQAB"
        + "-----END PUBLIC KEY-----"
    var pub_encrypt = new JSEncrypt();
    pub_encrypt.setPrivateKey(Ca_Pub);
    aes_key = randomWord(16);
    var post_data = {
        "key": pub_encrypt.encrypt(aes_key)
    }
    var keyHex = CryptoJS.enc.Utf8.parse(aes_key);
    post_data.email = encrypt($('#email').val(), keyHex)
    post_data.passwd = encrypt($('#password').val(), keyHex)
    $.ajaxSettings.async = false;
    $.post(
        window.key_host,
        post_data,
        function (data, status) {
            var cipher = data.privatekey;
            var private_key = decrypt(cipher, keyHex);
            localStorage.setItem(window.name, private_key);
            $('#prompt').html("<div class='alert alert-success' role='alert'> Authentication is complete, jumping to home page.</div>")
            setTimeout(function () {
                window.location.href = home_host;
            }, 1000);
        });
    $.ajaxSettings.async = true;
    window.event.returnValue = false;
}