function edit() {
    post_data = {};
    var pub_encrypt = get_serverPub();
    if ($('#opasswd').val() == "") {
        alert("请输入密码");
        $('#opasswd').focus();
        return false;
    }
    if ($('#name').val() != "") {
        post_data.name = pub_encrypt.encrypt($('#name').val());
    }
    if ($('#ppasswd').val() != "") {
        post_data.ppasswd = pub_encrypt.encrypt($('#ppasswd').val());
    }
    if ($('#card').val() != "") {
        post_data.card = pub_encrypt.encrypt($('#card').val());
    }
    if ($('#phone').val() != "") {
        post_data.phone = pub_encrypt.encrypt($('#phone').val());
    }
    else {
        post_data.opasswd = pub_encrypt.encrypt($('#opasswd').val());
    }
    $.ajaxSettings.async = false;
    $.post(
        window.location.href,
        post_data,
        function (data, status) {
            if (data.message) {
                alert(data.message);
            }
            if (data.success) {
                $.ajaxSettings.async = true;
                setTimeout(function () {
                    window.location.href = info_host;
                }, 1000);
            }
            return false;
        }
    )
    window.event.returnValue = false;
}