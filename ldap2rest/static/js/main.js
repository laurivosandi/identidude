


function onUserLoaded(user) {
    // Create list item representing user
    var $user = $("<li/>").attr("id", user.username).addClass("user").addClass("icon").append(user.cn ? user.cn + " (" + user.username + ")" : user.username);
  //  $user.attr("data-dn", distinguishedName);
  
    // Copy attributes
    for(key in user) {
        $user.attr("data-" + key, user[key]);
    }
    
    // Attach title
    $user.attr("title", "Viimati muudetud " + user.modified);
    
    // Prepend to the list
    $("#users ul").prepend($user);

    // Bind click event
    $($user).click(function() {
        $("#users .user").removeClass("selected");
        $(this).addClass("selected");
        $(this).after($("#users .details").show());
        $("#users .details .home").html($(this).attr("data-home"));
        window.location.hash = $(this).attr("data-username");
    });

    return $user;
}

function onUserListLoaded(status, users) {
    $("#users").append($("#users .details"));
    $("#users ul").empty();
    var count = 0;
    for (distinguishedName in users) {
        var $user = onUserLoaded(users[distinguishedName]);
        if (count >= 10) {
            $user.hide();
        }
        count++;
    } 
    console.info("Finished loading users");
    
    if (count > 10) {
        $("#users .status").show().html("Veel " + (count-10) + " kasutajat");
    } else {
        $("#users .status").hide();
    }
    
    $("#users .back").unbind().click(function() {
        $("content section").hide();
        $("#add-user").hide();
        $("#domains").show();
    });
}

function onDomainsLoaded(domains) {
    $("#domains .back").click(function() {
        $("content section").hide();
        $("#home").show();
    });

    $("#domains ul").empty();
    for (domain in domains) {
        var $domain = $("<li/>").addClass("icon").addClass("domain").attr("data-domain", domain).append(domains[domain]);
        $("#domains ul").append($domain);
    }
    
    $("#domains ul li").click(function() {
        var domain = $(this).attr("data-domain");
        $("#add-user .domain").val(domain);
        $("#add-domain").show();
        $("#domains").hide();
        $("#users").show();
        $("#add-user").show();
        $("#add-user .extra").hide();
        $("#users .status").html("Laadin kasutajaid");
        ldap.user_list(domain, onUserListLoaded);
    });
}

function onLogin(status, me) {
    if (status != 200) {
        alert(me.description);
        return;
    }
    
    localStorage["username"] = me.username;
    
    onProfileLoaded(200, me);
    
    $("content section").hide();
    $("#sidepanel").show();
    $("#home").show();
    $("#profile").show();
}

function onProfileLoaded(status, me) {
    console.info(me);
    if (status == 200) {
        window.ME = me;

        $("#profile .user").html(me.cn);
        $("#edit-profile .user").html(me.username);
        $("#edit-profile .home").html(me.home);
        $("#edit-profile input[name='mobile']").val(me.mobile);
        $("#edit-profile input[name='gender'][value='" + me.gender + "']").prop("checked", true);
        $("#edit-profile input[name='born']").val(me.born);
//        $("#edit-profile input[name='cn']").val(me.cn); TODO: CN edit requires object rename?
        $("#edit-profile input[name='email']").val(me.email);
        if (me.password_modified) {
            $("#edit-profile .date.password-modified").show().html(me.password_modified);
        } else {
            $("#edit-profile .date.password-modified").hide();
        }

        $("content section").hide();
        $("#profile").show();
        $("#home").show();
        
       
        if (me.managed_domains) {
            $("#home .managed-domains").show();
            onDomainsLoaded(me.managed_domains);
        } else {
            $("#home .managed-domains").hide();
        }
        
        console.info("Profile loaded:", status, me);
        
        ldap.groups(function(status, groups) {
            if (status != 200) {
                alert(groups.description);
            } else {
                $("#edit-profile .groups").empty();
                var count = 0;
                for (group in groups) {
                    console.info("Adding group:", group);
                    var $input = $("<input/>").attr("id", "edit-profile-group-" + group).attr("type", "checkbox").attr("name", group);
                    var $label = $("<label/>").attr("for", "edit-profile-group-" + group).append(groups[group].description);
                    $("#edit-profile .groups").append($input, $label);
                    $("#add-user form select.group").append($("<option/>").addClass("icon group").attr("value", group).html(groups[group].description));
                    count++;
                }
                if (count == 0) {
                    $("#edit-profile .groups").hide();
                    $("#add-user form select.group").hide();
                } else {
                    $("#edit-profile .groups").show();
                    $("#add-user form select.group").show();
                }
            }
        });
    } else {
        console.info("Failed to retrieve profile, going to show login section instead:", me);
        $("content section").hide();
        $("#log-in").show();
    }
}

$(document).ready(function() {
    ldap = new LDAP("/api");
    ldap.profile(onProfileLoaded);
    
    // Prefill username field in log-in view    
    if (localStorage.username) {
        $("#log-in .user").val(localStorage.username);
    }

    // Bind home screen links    

    
    $("#home .managed-domains").click(function() {
        $("content section").hide();
        $("#domains").show();
    });

    $("#home .edit-profile").click(function() {
        $("content section").hide();
        $("#edit-profile").show();
    });
    
    $("#edit-profile form").submit(function(e) {
        e.preventDefault();
        $("#edit-profile .save").addClass("busy");
        ldap.query("PUT", "/session/", $("#edit-profile form").serialize(), function(status, response) {
            $("#edit-profile .save").removeClass("busy");
            if (status != 200) {
                alert(response.description);
            } else {
                $("#edit-profile .back").trigger("click");
            }

        });
    });
   
    $("#edit-profile .back").click(function(e) {
        e.preventDefault();
        $("content section").hide();
        $("#home").show();
    });
    
    
    /**
     * Password change view
     */
    $("#change-password form").submit(function(e) {
        e.preventDefault();
        if ($("#change-password .new").val() != $("#change-password .confirm").val()) {
            alert("Paroolid ei klapi!");
            return;
        }

        $("#change-password button.change-password").addClass("busy");
        
        ldap.set_password(ME.domain, ME.username, $(this).serialize(), function(status, response) {

            $("#change-password button.change-password").removeClass("busy");
            if (status == 200) {
                $("#change-password .back").trigger("click");
            } else {
                alert(response.description);
            }
        });
        
    $("#users .details .change-password").click(function() {
        var newPass = $("#users .details .password-new").val()
        if (newPass != $("#users .details .password-confirm").val()) {
            alert("It is not the same!");
            return;
        }
        if (newPass.length < 8) {
            alert("Liiga lühike parool.");
            return;
        } 
        console.log(newPass);       
    });

    });
    
    $("#home .change-password").click(function() {
        $("content section").hide();
        $("#change-password").show();
        $("#change-password form .new").val("");
        $("#change-password form .confirm").val("");
    });
    
    $("#change-password .back").click(function() {
        $("content section").hide();
        $("#home").show();
    });
    


    /**
     * Authorized SSH keys view
     */
    $("#home .authorized-keys").click(function(e) {
        // Juggle views
        e.preventDefault();
        $("content section").hide();
        $("#authorized-keys").show();
        $("#authorized-keys ul").empty();
        
        // Rebind back button
        $("#authorized-keys .back").unbind().click(function() {
            $("content section").hide();
            $("#home").show();
        });
        
        $("#authorized-keys form").unbind().submit(function(e) {
            event.preventDefault();
            $("#authorized-keys .add-key").addClass("busy");
            alert("Not implemented");
/*            ldap.add_user($("#authorized--user .domain").val(), $("#add-user form").serialize(), function(status, u) {
                $("#add-user .add-user").removeClass("busy");
                if (status != 200) {
                    alert(u.description, u.title);
                } else {
                    console.info("User added:", status, u);
                    $('#add-user form').trigger("reset");
                    onUserLoaded(u);
                }
            });*/

        });
     
        // Fetch added keys
        ldap.authorized_keys(function(status, authorized_keys) {
            var count = 0;
            for (username in authorized_keys) {
                var attributes = authorized_keys[username];
                var $key = $("<li/>").addClass("key").addClass("icon").html(attributes.authorized_keys);
    //            $user.attr("data-dn", distinguishedName);
    //        for(key in user) {
    //            $user.attr("data-" + key, user[key]);
    //        }
    //            $user.attr("title", "Viimati muudetud " + user.modified);
                $("#authorized-keys ul").append($key);
                count++;
            }
            
            if (count == 0) {
                $("#authorized-keys .status").html("Ühtegi võtit pole lisatud veel!");
            } else {
                $("#authorized-keys .status").html("Leiti " + count + " võtit");
            }

        });
    });


    /**
     * Login
     */
    $("#profile .log-out").click(function() {
        console.info("Deleting cookie");
        document.cookie = 'token=; Path=/api/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
        $("content section").hide();
        $("aside").hide();
        $("#log-in").show();
    });
    
    $("#log-in .log-in").click(function() {
        var username = $("#log-in .user").val();
        var password = $("#log-in input[type='password']").val();
        $("#log-in input[type='password']").val("");
        ldap.bind(username, password, onLogin);
    });
    

    function onAddUserNameChanged() {
        var bits = $("#add-user .name").val().toLowerCase();
        MAPPING = {
            "õ": "o", "Õ": "O",
            "ö": "o", "Ö": "O",
            "ä": "a", "Ä": "A",
            "ü": "u", "Ü": "U",
            "š": "s", "Š": "S",
            "ž": "z", "Ž": "Z"
        }
        for (key in MAPPING) {
            bits = bits.replace(key, MAPPING[key]);
        }
        bits = bits.split(" ");
        $("#add-user .user").val(bits[0][0] + bits[bits.length-1] + $("#add-user .id-lookup").val().substring(7));
    }
    
    
    /**
     * User list view
     */

    $("#add-user .id-lookup").change(function() {
        $("#add-user .id-lookup").addClass("busy");
        $("#add-user form input[name='cn']").val("");
        $("#add-user form input[name='email']").val("");
        $("#add-user form input[name='mobile']").val("");
        $("#add-user .extra").fadeIn();
        var id = $(this).val();
        ldap.lookup(id, function(status, details) {
            $("#add-user .id-lookup").removeClass("busy");
            if (id in details) {
                $("#add-user form input[name='cn']").val(details[id].gn + " " + details[id].sn);
                $("#add-user form input[name='username']").val(details[id].username);
                $("#add-user form input[name='email']").val(details[id].email);
                onAddUserNameChanged();
            }
        });
    });
    
    // Full name change causes regeneration of suggested username
    $("#add-user form input[name='cn']").change(onAddUserNameChanged);
    
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
    
    // Bind user lock button
    $("#users .details .lock").click(function() {
        ldap.lock_user($(this).attr("data-domain"), $(this).attr("data-username"));
    });
    
    // Bind user delete button
    $("#users .details .userdel").click(function() {
        var $selected = $("#users ul li.selected");

        if (confirm("Oled kindel et soovid kustutada kasutaja " + $selected.attr("data-cn") + " (" + $selected.attr("data-username") + ")?")) {
            $("#users .details .userdel").addClass("busy");
            ldap.userdel($selected.attr("data-domain"), $selected.attr("data-username"), function(status, o) {
                $("#users .details .userdel").removeClass("busy");
                if (status == 200) {
                    $("#users ul li.selected").remove();
                    if ($("#users ul li:visible").size() > 0) {
                        $("#users ul li:visible").first().trigger("click");
                    } else {
                        $("#users .details").hide();
                    }
                } else {
                    alert(o.description);
                }
            });
        }
    });
    
    // Bind user password reset button
    $("#users .details .reset-password").click(function() {
        var $selected = $("#users ul li.selected");

        if (confirm("Oled kindel et soovid lähtestada kasutaja " + $selected.attr("data-cn") + " (" + $selected.attr("data-username") + ") parooli?")) {
            $("#users .details .reset-password").addClass("busy");
            ldap.reset_password($selected.attr("data-domain"), $selected.attr("data-username"), function(status, o) {
                $("#users .details .reset-password").removeClass("busy");
                if (status == 200) {
                    alert("Ajutine parool saadeti e-posti aadressidele: " + o.recipients.join(", "));
                } else {
                    alert(o.description);
                }
            });
        }
    });

    // Bind user search box   
    $("#users .search").on("keyup", function(e) {

        if (e.keyCode != 13) {
            return;
        }
        var query = $("#users .search").val().toLowerCase();
        console.info("Searching for:", query);
        var count = 0;
        $("#users ul li.user").each(function(index) {
            if ($(this).attr("data-cn").toLowerCase().indexOf(query) >= 0 || $(this).attr("data-username").toLowerCase().indexOf(query) >= 0) {
                count++;
                $(this).show();
            } else {
                $(this).hide();
            }
        });
        $("#users .status").html("Leitud " + count + " kasutajat");
   });
});



