function change(name) {
    $(document).ready(function () {
        $("#home").removeClass("active");
        $("#recharge").removeClass("active");
        $("#withdraw").removeClass("active");
        $("#transfer").removeClass("active");
        $("#bills").removeClass("active");
        $("#info").removeClass("active");
        $("#edit").removeClass("active");
        $("#" + name).addClass("active");
    });
}
//BEGIN COUNTER FOR SUMMARY BOX
function counterNum(obj, start, end, step, duration) {
    $(obj).html(start);
    setInterval(function () {
        var val = Number($(obj).html());
        if (val < end) {
            $(obj).html(val + step);
        } else {
            $(obj).html(end);
            clearInterval();
        }
    }, duration);
}
    //END COUNTER FOR SUMMARY BOX