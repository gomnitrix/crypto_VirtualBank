function signin() {
    var post_data = {
        "si_request": true
    };
    $.post(
        signin_host,
        post_data,
        function (data, status) {
            pub_key = data.pub_key;
            salt = data.salt;
            salt_id = data.salt_id;
            var encrypt = new JSEncrypt();
            encrypt.setPublicKey(pub_key);
            post_data.si_request = false;
            post_data.name = encrypt.encrypt($('#username').val());
            var first = CryptoJS.MD5($('#password').val()).toString()
            var after = CryptoJS.MD5(first + salt).toString()
            post_data.passwd = encrypt.encrypt(after);
            post_data.salt_id = salt_id;
            $.post(
                signin_host,
                post_data,
                function (data, status) {
                    if (data.if_success) {
                        window.location.href = data.url;
                    }
                    var message = data.message
                    if (message) {
                        $('#prompt').html("<div class='alert alert-success' role='alert'>" + message + ".</div>")
                    }
                    return false
                }
            )
        });
    window.event.returnValue = false;
}

function pay() {
    var phone = $('#phone').val();
    var passwd = $('#password').val();
    if (phone == "") {
        alert("请填写预留电话号码");
        $('#phone').focus();
        return false;
    }
    if (passwd == "") {
        alert("请填写支付密码");
        $('#password').focus();
        return false;
    }
    var post_data = {
        "pay_request": true
    };
    pub_key = get_serverPub();
    post_data.phone = pub_key.encrypt(phone);
    post_data.passwd = pub_key.encrypt(passwd);
    post_data.pay_id = pub_key.encrypt(window.pay_id);
    $.post(
        window.pay_host,
        post_data,
        function (data, status) {
            var message = data.message;
            if (message) {
                $('#prompt').html("<div class='alert alert-success' role='alert'>" + message + ".</div>")
            }
            var url = data.flag;
            if (url) {
                setTimeout(function () {
                    window.location.href = "http://192.168.43.59:8000/ca/get_sign";
                }, 2000);
            }
        }
    )
    window.event.returnValue = false;
}