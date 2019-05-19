
function setpay() {
    var post_data = { "set": true };
    var setpay_host = window.location.href;
    var passwd = document.getElementById("password");
    var re_passwd = document.getElementById("re-password");
    if (passwd.value != re_passwd.value) {
        alert("两次密码不一致");
        $('#password').val("");
        $('#re-password').val("");
        passwd.focus();
        return false;
    }
    $.post(
        setpay_host,
        post_data,
        function (data, status) {
            pub_key = data.pub_key
            var encrypt = new JSEncrypt();
            encrypt.setPublicKey(pub_key);
            post_data.set = false;
            post_data.passwd = encrypt.encrypt($('#password').val());
            $.post(
                setpay_host,
                post_data,
                function (data, status) {
                    var message = data.message
                    if (message) {
                        $('#prompt').html("<div class='alert alert-success' role='alert'>" + message + ".</div>")
                    }
                    if (data.url) {
                        setTimeout(function () {
                            window.location.href = data.url;
                        }, 2000);
                    }
                    return false
                }
            )
        });
    window.event.returnValue = false;
}