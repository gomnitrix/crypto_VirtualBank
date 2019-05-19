function transfer()
{
    if ($('#phone').val() == "") {
        alert("请填写联系电话");
        $('#name').focus();
        return false;
    }
    if ($('#b_phone').val() == "") {
        alert("请填写收款人电话号码");
        $('#b_phone').focus();
        return false;
    }
    if ($('#amount').val() == "") {
        alert("请填写银行卡号");
        $('#amount').focus();
        return false;
    }
    if ($('#passwd').val() == "" || $('#retype').val() == "") {
        alert("请输入密码");
        $('#passwd').focus();
        return false;
    }
    if ($('#passwd').val() != $('#retype').val()) {
        alert("两次密码不一致");
        $('#passwd').val("");
        $('#retype').val("");
        $('#passwd').focus();
        return false;
    }
    var salt = getsalt();
    var pub_encrypt = get_serverPub();
    post_data = {};
    post_data.amount = pub_encrypt.encrypt($('#amount').val());
    var first = CryptoJS.MD5($('#passwd').val()).toString()
    var after = CryptoJS.MD5(first + salt).toString()
    post_data.passwd = pub_encrypt.encrypt(after);
    post_data.b_phone = pub_encrypt.encrypt($('#b_phone').val());
    post_data.phone = pub_encrypt.encrypt($('#phone').val());
    var pri_encrypt = get_private();
    post_data.signature = pri_encrypt.sign(post_data.amount + post_data.passwd+ post_data.b_phone+ post_data.phone, CryptoJS.SHA256, "sha256");
    $.ajaxSettings.async = false;
    $.post(
        window.location.href,
        post_data,
        function (data, status) {
            if (data.message) {
                $('#prompt').html("<div class='alert alert-success' role='alert'>" + data.message + ".</div>")
            }
            if (data.success) {
                $.ajaxSettings.async = true;
                setTimeout(function () {
                    window.location.href = home_host;
                }, 1000);
            }
            return false;
        }
    )
    window.event.returnValue = false;
}