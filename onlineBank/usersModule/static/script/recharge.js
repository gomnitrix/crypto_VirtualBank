function getsalt(){
    var salt;
    $.ajaxSettings.async = false;
    $.post(
        window.salt_host,
        '',
        function (data, status) {
            salt = data.salt;
        }
    )
    $.ajaxSettings.async = true;
    return salt;
}
function recharge() {
    var salt = getsalt();
    var pub_encrypt = get_serverPub();
    post_data = {};
    post_data.amount = pub_encrypt.encrypt($('#amount').val());
    var first = CryptoJS.MD5($('#password').val()).toString()
    var after = CryptoJS.MD5(first + salt).toString()
    post_data.passwd = pub_encrypt.encrypt(after);
    var pri_encrypt = get_private();
    post_data.signature = pri_encrypt.sign(post_data.amount + post_data.passwd, CryptoJS.SHA256, "sha256");
    console.log(post_data);
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