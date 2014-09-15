function LDAP(url) {
    this.url = url;
    
    this.query = function(method, endpoint, params, onLoad, onError) {
        var request = new XMLHttpRequest();
        var body = "";
        if (typeof params === "string" || params instanceof String) { // Seems like a completely sane thing to do
            body = params;
        } else {
            for (key in params) {
                body += key;
                body += "=";
                body += encodeURIComponent(params[key]);
                body += "&";
            }
        }

        if (method == "GET" || method == "HEAD") {
            endpoint += "?";
            endpoint += body;
            body = "";
        }
        var url = this.url + endpoint;
        request.open(method, url, true);
        request.onload = function() {
            var data = {};
            
            if (request.status == 503) {
                data = { title:"Error", description:"Service temporarily unavailable, please check again later" };
            } else if (request.status == 502) {
                data = { title:"Error", description:"Whoops, it seems the application has stopped responding on the server, please check again later"};
            } else if (request.status == 500) {
                data = { title:"Error", description:"Whoops, it seems server has stumbled upon an error in the code. Please contact lauri.vosandi@gmail.com" };
            } else if (request.responseText != "") {
                try {
                    data = JSON.parse(request.responseText)
                } catch(e) {
                    console.error("Failed to parse JSON:", request.responseText);
                    data.description = request.responseText;
                    data.title = "Error"; 
                }
            }
            
            onLoad(request.status, data);
        }
        request.onerror = onError;
        
        if (body) {
           request.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
        }
        
        // Hide password from logs
        if (params.password) { params.password = "***"; }
        console.debug("Method:", method, "Endpoint:", endpoint, "Body:", params);
        request.send(body);
    }
    
    this.profile = function(onLoad) {
        this.query("GET", "/session/", {}, onLoad);
    }
    
    this.bind = function(username, password, onLoad) {
        this.query("POST", "/session/", {username:username, password:password}, onLoad);
    }
    
    this.user_list = function(domain, onLoad) {
        this.query("GET", "/domain/" + domain + "/user/", {}, onLoad);
    }
    
    this.add_user = function(domain, attributes, onLoad) {
        this.query("POST", "/domain/" + domain + "/user/", attributes, onLoad);
    }
    
    this.userdel = function(domain, username, onLoad) {
        this.query("DELETE", "/domain/" + domain + "/user/" + username, {}, onLoad);
    }
    
    this.reset_password = function(domain, username, onLoad) {
        this.query("PUT", "/domain/" + domain + "/user/" + username + "/password/", {}, onLoad);
    }
    
    this.lock_account = function(domain, username, onLoad) {
        this.query("DELETE", "/domain/" + domain + "/user/" + username + "/password/", {}, onLoad);
    }

    
    this.authorized_keys = function(onLoad) {
        this.query("GET", "/authorized_keys/", {}, onLoad);
    }
    
    this.lookup = function(ids, onLoad) {
        this.query("GET", "/lookup/", {ids: ids}, onLoad);
    }
    
    this.groups = function(onLoad) {
        this.query("GET", "/group/", {}, onLoad);
    }
}

