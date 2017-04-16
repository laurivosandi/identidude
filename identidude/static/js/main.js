

views = {}

views.index = function() {
    $("#users").show();
}

views.user = function(username) {
    console.info("opening user view:", username);

    $.ajax({
        method: "GET",
        url: "/api/user/" + username + "/",
        dataType: "json"
    }).done(function(user, status, xhr) {
        console.info("User details loaded:", user);
        user.password_expired = new Date(new Date(user.password_set).getTime() + session.domain.max_password_age * 1000); // wth js
        $("#profile").html(nunjucks.render('views/user-detail.html', { user: user, window:window })).show();
    }).fail(function(response) {
        if (response.responseJSON) {
            var msg = response.responseJSON
        } else {
            var msg = { title: "Error " + response.status, description: response.statusText }
        }
    });
}

function userSubmit(e) {
    // Create user
    $(e).addClass("busy");
    var user = $("#add-user form").serializeArray();
    $.ajax({
        method: "POST",
        url: "/api/user/",
        data: user,
        dataType: "json",
    }).done(function(response, status, xhr) {
        console.info("User created sucessfully");
    }).fail(function(xhr, status) {
        alert(xhr.responseJSON.description);
    }).always(function() {
        $(e).removeClass("busy");
    });
}

function userLookup(inp) {
    var id = inp.value;
    $.ajax({
        method: "GET",
        url: "/api/lookup?ids=" + id,
        dataType: "json",
        error: function(response) {
            alert(response.description);
        },
        success: function(users, status, xhr) {
            console.info("Great success:", users);
            var user = users[id];
            console.info("User:", user);
            $("#add-user form input[name='mail']").val(user.mail);
            $("#add-user form input[name='gn']").val(user.gn);
            $("#add-user form input[name='sn']").val(user.sn);
            $("#add-user form input[name='name']").val(user.name);
            $("#add-user form select[name='gender'").val(user.gender);
            $("#add-user form input[name='birthday']").val(user.birthday);
            $("#add-user form .certificates").remove();
            for (index in user.certificates) {
                $("#add-user form").append("<input type='hidden' name='certificates' value='" +user.certificates[index] + "'/>");
            }

        }
    });
}

function userSearch(inp) {
    clearTimeout(window.userSearchTimeout);
    window.userSearchTimeout = setTimeout(function() {
        $("#users li,#group li").each(function(i,v) {
            v.style.display = v.dataset.keywords.toLowerCase().indexOf(inp.value) >= 0 ? "block" : "none"
        });
    },200);
}

function userDelete(btn) {
    if (confirm("Are you sure you want to delete user " + window.view)) {
        $(btn).addClass("busy");
        $.ajax({
            method: "DELETE",
            url: "/api" + window.view,
        }).done(function() {
            console.info("Succesfully deleted user:", window.view);
            userCancel();
        }).fail(function() {
            console.info("Failed to delete user");
        }).always(function() {
            $(btn).removeClass("busy");
        });
    }
}

function userCancel() {
    $("#profile").empty();
    window.location.hash = "/";
}

function userSave(btn) {
    $(btn).addClass("busy");
    var user = $("#profile form").serializeArray();
    $.ajax({
        method: "PUT",
        url: "/api" + window.view,
        data: user
    }).done(function() {
        console.info("User changes saves");
        userCancel();
    }).fail(function(xhr, status, e) {
        $(btn).removeClass("busy");
        alert(xhr.responseJSON.description);
    });
}

function onUserClicked(e) {
    window.location.hash = "/user/" + e.dataset.username + "/";
}

function onHashChanged() {
    if (window.location.hash.indexOf("#") < 0) {
        return;
    }
    $("container").hide();

    if (window.location.hash == "#/") {
        window.view = "/";
        views.index();
    } else {
        var myRegexp = /#\/(.+)\/(.+)\//g;
        var m = myRegexp.exec(window.location.hash);
        window.view = window.location.hash.substring(1);
        views[m[1]](m[2]);
    }
}


$(document).ready(function() {
    $("#add-user").html(nunjucks.render("views/user-add.html"));

    $.ajax({
        method: "GET",
        url: "/api/",
        dataType: "json",
        error: function(response) {
            if (response.responseJSON) {
                var msg = response.responseJSON
            } else {
                var msg = { title: "Error " + response.status, description: response.statusText }
            }
            $("#container").html(nunjucks.render('views/error.html', { message: msg }));
            alert(msg.description);
        },
        success: function(session, status, xhr) {
            console.info("Session:", session);
            $("#users section").html(nunjucks.render('views/user-list.html', { session: session, window: window }));
            $("#users input[type='search']").focus();
            window.session = session;
            onHashChanged();
        }
    });

    return;

    // E-mail change causes e-mail notification tick/untick and enable/disable
    $("#add-user form input[name='email']").change(function() {
        if ($(this).val() == "") {
            $("#add-user-notify").prop('disabled', true);
            $("#add-user-notify").prop('checked', false);
        } else {
            $("#add-user-notify").prop('disabled', false);
            $("#add-user-notify").prop('checked', true);
        }
    });

    // Bind form submission button
    $("#add-user form").submit(function(e) {
        e.preventDefault();
        $("#add-user .add-user").addClass("busy");
        ldap.add_user($("#add-user .domain").val(), $("#add-user form").serialize(), function(status, u) {
            $("#add-user .add-user").removeClass("busy");
            if (status != 200) {
                alert(u.description);
            } else {
                $("#add-user .extra").fadeOut();
                console.info("User added:", status, u);
                $('#add-user form').trigger("reset");
                onUserLoaded(u);
            }
        });
    });


});



