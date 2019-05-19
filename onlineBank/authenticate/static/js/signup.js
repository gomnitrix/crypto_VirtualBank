function signup() {
    var name = document.getElementById("name");
    var phone = document.getElementById("phone");
    var card = document.getElementById("card");
    var id = document.getElementById("id_no");
    var passwd = document.getElementById("password");
    var re_passwd = document.getElementById("re-password");
    var post_data = {
        'signup_request': true,
    };
    var pub_key;
    if ($('#name').val() == "") {
        alert("请填写用户名");
        name.focus();
        return false;
    }
    if (phone.value == "") {
        alert("请填写联系电话"); 
        phone.focus();
        return false;
    }
    if (id.value == "") {
        alert("请填写身份证号码");
        id.focus();
        return false;
    }
    if (card.value == "") {
        alert("请填写银行卡号");
        card.focus();
        return false;
    }
    if (passwd.value == "" || re_passwd.value == "") {
        alert("请输入密码");
        passwd.focus();
        return false;
    }
    if (passwd.value != re_passwd.value) {
        alert("两次密码不一致");
        $('#password').val("");
        $('#re-password').val("");
        passwd.focus();
        return false;
    }
    $.post(
        post_host,
        post_data,
        function (data, status) {
            pub_key = data.pub_key
            var encrypt = new JSEncrypt();
            encrypt.setPublicKey(pub_key);
            post_data.signup_request = false;
            post_data.name = encrypt.encrypt(name.value);
            post_data.phone = encrypt.encrypt(phone.value);
            post_data.id_no = encrypt.encrypt(id.value);
            post_data.card = encrypt.encrypt(card.value);
            post_data.passwd = encrypt.encrypt(passwd.value);
            console.log(post_data);
            $.post(
                post_host,
                post_data,
                function (data, status) {
                    console.log(data);
                    if (data.saved){
                        window.location.href=prompt_host;
                    }
                    return data.saved;
                })
            return false;
        });
    window.event.returnValue=false;  
}
function re_direct() {
    window.location.href = signin_host;
    window.event.returnValue=false;
}