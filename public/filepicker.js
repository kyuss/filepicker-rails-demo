(function(){
    var fp = (function(){
        var context = {};
        var addObjectTo = function(name, obj, base){
            var path = name.split(".");
            for (var i = 0; i < path.length - 1; i++) {
                if (!base[path[i]]) {
                    base[path[i]] = {};
                }
                base = base[path[i]];
            }
            if (typeof obj === "function") {
                if (obj.isClass) {
                    //We don't do fancy apply tricks because they don't work with new
                    base[path[i]] = obj;
                } else {
                    base[path[i]] = function(){return obj.apply(context, arguments);};
                }
            } else {
                base[path[i]] = obj;
            }
        };
        
        var extendObject = function(name, obj, is_public) {
            addObjectTo(name, obj, context);
            if (is_public) {
                addObjectTo(name, obj, window.filepicker);
            }
        };

        var extend = function(pkg, init_fn, is_public){
            if (typeof pkg === "function") {
                is_public = init_fn;
                init_fn = pkg;
                pkg = ''; 
            }

            if (pkg) {
                pkg += ".";
            }
            var objs = init_fn.call(context);
            for (var obj_name in objs) {
                extendObject(pkg+obj_name, objs[obj_name], is_public);
            }
        };

        //So we can access the internal scope until the very end when we delete this call
        var internal = function(fn) {
            fn.apply(context, arguments);
        };

        return {
            extend: extend,
            internal: internal
        };

    })();

    //Initializing
    if (!window.filepicker){
        window.filepicker = fp;
    } else {
        for (attr in fp) {
            window.filepicker[attr] = fp[attr];
        }
    }
})();
//ajax.js
filepicker.extend("ajax", function(){
    var fp = this;

    var get_request = function(url, options) {
        options['method'] = 'GET';
        make_request(url, options);
    };

    var post_request = function(url, options) {
        options['method'] = 'POST';
        url += (url.indexOf('?') >= 0 ? '&' : '?') + '_cacheBust='+fp.util.getId();
        make_request(url, options);
    };

    var toQueryString = function(object, base) {
        var queryString = [];
        for (var key in object) {
            var value = object[key];
            if (base) key = base + '[' + key + ']';
            var result;
            switch (fp.util.typeOf(value)){
                case 'object': result = toQueryString(value, key); break;
                case 'array':
                    var qs = {};
                    for (var i = 0; i < value.length; i++) {
                        qs[i] = value[i];
                    }
                    result = toQueryString(qs, key);
                break;
                default: result = key + '=' + encodeURIComponent(value); break;
            }
            if (value !== null){
                queryString.push(result);
            }
        }

        return queryString.join('&');
    };

    var getXhr = function() {
        try{
            // Modern browsers
            return new window.XMLHttpRequest();
        } catch (e){
            // IE
            try{
                return new window.ActiveXObject("Msxml2.XMLHTTP");
            } catch (e) {
                try{
                    return new window.ActiveXObject("Microsoft.XMLHTTP");
                } catch (e){
                    // Something went wrong
                    return null;
                }
            }
        }
    };

    var make_request = function(url, options) {
        //setting defaults
        url = url || "";
        var method = options.method ? options.method.toUpperCase() : "POST";
        var success = options.success || function(){};
        var error = options.error || function(){};
        var async = options.async === undefined ? true : options.async;
        var data = options.data || null;
        var processData = options.processData === undefined ? true : options.processData;
        var headers = options.headers || {};
        
        var urlParts = fp.util.parseUrl(url);
        var origin = window.location.protocol + '//' + window.location.host;
        var crossdomain = origin !== urlParts.origin;
        var finished = false;

        //var crossdomain = window.location
        if (data && processData) {
            data = toQueryString(options.data);
        }

        //creating the request
        var xhr;
        if (options.xhr) {
            xhr = options.xhr;
        } else {
            xhr = getXhr();
            if (!xhr) {
                options.error("Ajax not allowed");
                return xhr;
            }
        }

        if (crossdomain && window.XDomainRequest && !("withCredentials" in xhr)) {
            return XDomainAjax(url, options);
        }

        if (options.progress && xhr.upload) {
            xhr.upload.addEventListener("progress", function(e){
                if (e.lengthComputable) {
                    options.progress(Math.round((e.loaded * 95) / e.total));
                }
            }, false);
        }

        //Handlers
        var onStateChange = function(){
            if(xhr.readyState == 4 && !finished){
                if (options.progress) {options.progress(100);}
                if (xhr.status >= 200 && xhr.status < 300) {
                    //TODO - look into using xhr.responseType and xhr.response for binary blobs. Not sure what to return
                    var resp = xhr.responseText;
                    if (options.json) {
                        try {
                            resp = fp.json.decode(resp);
                        } catch (e) {
                            onerror.call(xhr, "Invalid json: "+resp);
                            return;
                        }
                    }
                    success(resp, xhr.status, xhr);
                    finished = true;
                } else {
                    onerror.call(xhr, xhr.responseText);
                    finished = true;
                }
            }
        };
        xhr.onreadystatechange = onStateChange;

        var onerror = function(err) {
            //already handled
            if (finished) {return;}

            if (options.progress) {options.progress(100);}

            finished = true;
            if (this.status == 400) {
                error("bad_params", this.status, this);
                return;
            } else if (this.status == 403) {
                error("not_authorized", this.status, this);
                return;
            } else if (this.status == 404) {
                error("not_found", this.status, this);
                return;
            }
            if (crossdomain) {
                if (this.readyState == 4 && this.status === 0) {
                    error("CORS_not_allowed", this.status, this);
                    return;
                } else {
                    error("CORS_error", this.status, this);
                    return;
                }
            }

            //if we're here, we don't know what happened
            error(err, this.status, this);
        };

        xhr.onerror = onerror;

        //Executing the request
        if (data && method == 'GET') {
            url += (url.indexOf('?') != -1 ? '&' : '?') + data;
            data = null;
        }
        
        xhr.open(method, url, async);
        if (options.json) {
            xhr.setRequestHeader('Accept', 'application/json, text/javascript');
        } else {
            xhr.setRequestHeader('Accept', 'text/javascript, text/html, application/xml, text/xml, */*');
        }

        var contentType = headers['Content-Type'] || headers['content-type'];
        if (data && processData && (method == "POST" || method == "PUT") && contentType == undefined) {
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=utf-8');
        }

        if (headers) {
            for (var key in headers) {
                xhr.setRequestHeader(key, headers[key]);
            }
        }

        xhr.send(data); 

        return xhr;
    };

    //Ajax using XDomainRequest - different enough from normal xhr that we do it separately
    var XDomainAjax = function(url, options) {
        if (!window.XDomainRequest) {return null;}

        var method = options.method ? options.method.toUpperCase() : "POST";
        var success = options.success || function(){};
        var error = options.error || function(){};
        var data = options.data || {};

        //protocol of the url must match our protocol
        if (window.location.protocol == "http:") {
            url = url.replace("https:","http:");
        } else if (window.location.protocol == "https:") {
            url = url.replace("http:","https:");
        }

        /*
        if (options.headers['Content-Type']) {
            //custom content type, so we smush the data into a {data: data}
            data = {'data': data};
            data['mimetype'] = options.headers['Content-Type'];
        }
        */

        if (options.async) {
            throw new fp.FilepickerException("Asyncronous Cross-domain requests are not supported");
        }

        //Only supports get and post
        if (method != "GET" && method != "POST") {
            data["_method"] = method;
            method = "POST";
        }

        if (options.processData !== false) {
            data = data ? toQueryString(data) : null;
        }

        //Executing the request
        if (data && method == 'GET') {
            url += (url.indexOf('?') >= 0 ? '&' : '?') + data;
            data = null;
        }
        
        //so we know it's an xdr and can handle appropriately
        url += (url.indexOf('?') >= 0 ? '&' : '?') + '_xdr=true&_cacheBust='+fp.util.getId();

        var xdr = new window.XDomainRequest();
        xdr.onload = function() {
            var resp = xdr.responseText;
            if (options.progress) {options.progress(100);}
            if (options.json) {
                try {
                    resp = fp.json.decode(resp);
                } catch (e) {
                    error("Invalid json: " + resp, 200, xdr);
                    return;
                }
            }
            //assume status == 200, since we can't get it for real
            success(resp, 200, xdr);
        };
        xdr.onerror = function() {
            if (options.progress) {options.progress(100);}
            error(xdr.responseText || "CORS_error", this.status || 500, this);
        };
        //Must have an onprogress or ie will abort
        xdr.onprogress = function(){};
        xdr.ontimeout = function(){};
        xdr.timeout = 30000;
        //we can't set any headers
        xdr.open(method, url, true);
        xdr.send(data);
        return xdr;
    };

    return {
        get: get_request,
        post: post_request,
        request: make_request
    };
});
//base64.js
filepicker.extend("base64", function(){
    var fp = this;
    /**
    *
    *  Base64 encode / decode
    *  http://www.webtoolkit.info/
    *
    **/    
    // private property
    var _keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    // public method for encoding
    var encode = function (input, utf8encode) {
        utf8encode = utf8encode || utf8encode === undefined;

        var output = "";
        var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
        var i = 0;

        if (utf8encode) {
            input = _utf8_encode(input);
        }

        while (i < input.length) {
            chr1 = input.charCodeAt(i);
            chr2 = input.charCodeAt(i+1);
            chr3 = input.charCodeAt(i+2);
            i += 3;

            enc1 = chr1 >> 2;
            enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
            enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
            enc4 = chr3 & 63;

            if (isNaN(chr2)) {
                enc3 = enc4 = 64;
            } else if (isNaN(chr3)) {
                enc4 = 64;
            }

            output = output +
            _keyStr.charAt(enc1) + _keyStr.charAt(enc2) +
            _keyStr.charAt(enc3) + _keyStr.charAt(enc4);

        }
        return output;
    };

    // public method for decoding
    var decode = function (input, utf8decode) {
        utf8decode = utf8decode || utf8decode === undefined;
        var output = "";
        var chr1, chr2, chr3;
        var enc1, enc2, enc3, enc4;
        var i = 0;

        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        while (i < input.length) {

            enc1 = _keyStr.indexOf(input.charAt(i));
            enc2 = _keyStr.indexOf(input.charAt(i+1));
            enc3 = _keyStr.indexOf(input.charAt(i+2));
            enc4 = _keyStr.indexOf(input.charAt(i+3));
            i+=4;

            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;

            output = output + String.fromCharCode(chr1);

            if (enc3 != 64) {
                output = output + String.fromCharCode(chr2);
            }
            if (enc4 != 64) {
                output = output + String.fromCharCode(chr3);
            }

        }

        if (utf8decode) {
            output = _utf8_decode(output);
        }

        return output;
    };

    // private method for UTF-8 encoding
    var _utf8_encode = function (string) {
        string = string.replace(/\r\n/g,"\n");
        var utftext = "";

        for (var n = 0; n < string.length; n++) {

            var c = string.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            }
            else if((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            }
            else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }

        }

        return utftext;
    };

    // private method for UTF-8 decoding
    var _utf8_decode = function (utftext) {
        var string = "";
        var i = 0;
        var c = c1 = c2 = 0;

        while ( i < utftext.length ) {

            c = utftext.charCodeAt(i);

            if (c < 128) {
                string += String.fromCharCode(c);
                i++;
            }
            else if((c > 191) && (c < 224)) {
                c2 = utftext.charCodeAt(i+1);
                string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                i += 2;
            }
            else {
                c2 = utftext.charCodeAt(i+1);
                c3 = utftext.charCodeAt(i+2);
                string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                i += 3;
            }

        }

        return string;
    };

    return {
        encode: encode,
        decode: decode
    };
}, true);
//browser.js
filepicker.extend("browser", function(){
    var fp = this;

    var isIOS = function() {
        return !!(navigator.userAgent.match(/iPhone/i) ||
                navigator.userAgent.match(/iPod/i) ||
                navigator.userAgent.match(/iPad/i));
    };

    var isAndroid = function() {
        return !!navigator.userAgent.match(/Android/i);
    };

    var isIE7 = function() {
        return !!navigator.userAgent.match(/MSIE 7\.0/i);
    };

    return {
        isIOS: isIOS,
        isAndroid: isAndroid,
        isIE7: isIE7
    };
});
//comm.js
filepicker.extend("comm", function(){
    var fp = this;

    var COMM_IFRAME_NAME = "filepicker_comm_iframe";

    /*
     * Opens the IFrame if there isn't one
     */
    var openCommIframe = function(){
        if (window.frames[COMM_IFRAME_NAME] === undefined) {
            //Attach a event handler
            openCommunicationsChannel();

            //Opening an iframe to send events
            var commIFrame;
            commIFrame = document.createElement("iframe");
            commIFrame.id = commIFrame.name = COMM_IFRAME_NAME;
            commIFrame.src = fp.urls.COMM;
            commIFrame.style.display = 'none';
            document.body.appendChild(commIFrame);
        }
    };

    var communicationsHandler = function(event){
        if (event.origin != fp.urls.BASE && event.origin != fp.urls.DIALOG_BASE) {return;}
        var data = fp.json.parse(event.data);
        fp.handlers.run(data);
    };

    /*
     * 1. Creates the general communcation handler
     * 2. Set to listen
     * ONLY RUN ONCE
     */
    var isOpen = false;

    var openCommunicationsChannel = function(){
        if (isOpen){
            return;
        } else {
            isOpen = true;
        }


        //Modern
        if (window.addEventListener) {
            window.addEventListener("message", communicationsHandler, false);
        //IE8, FF3
        } else if (window.attachEvent) {
            window.attachEvent("onmessage", communicationsHandler);
        //No hope
        } else {
            throw new fp.FilepickerException("Unsupported browser");
        }
    };

    var destroyCommIframe = function(){
        //Modern
        if (window.removeEventListener) {
            window.removeEventListener("message", communicationsHandler, false);
        //IE8, FF3
        } else if (window.attachEvent) {
            window.detachEvent("onmessage", communicationsHandler);
        //No hope
        } else {
            throw new fp.FilepickerException("Unsupported browser");
        }

        if (!isOpen){
            return;
        } else {
            isOpen = false;
        }
        //Also removing iframe
        var iframes = document.getElementsByName(COMM_IFRAME_NAME);
        for (var i = 0; i < iframes.length; i++){
            iframes[i].parentNode.removeChild(iframes[i]);
        }
        try{delete window.frames[COMM_IFRAME_NAME];}catch(e){}
    };

    return {
        openChannel: openCommIframe,
        closeChannel: destroyCommIframe
    };
});
//comm_fallback.js
filepicker.extend("comm_fallback", function(){
    var fp = this;

    var FP_COMM_IFRAME_NAME = "filepicker_comm_iframe";
    var HOST_COMM_IFRAME_NAME = "host_comm_iframe";
    var base_host_location = "";
    var hash_check_interval = 200;

    /*
     * Opens the IFrame if there isn't one
     */
    var openCommIframe = function(){
        openHostCommIframe();
    };

    //First we open a host comm iframe to test what the url is we'll be working with on the host
    //to make sure we don't run into redirect issues
    var openHostCommIframe = function(){
        if (window.frames[HOST_COMM_IFRAME_NAME] === undefined) {
            //Opening an iframe to send events
            var hostCommIFrame;
            hostCommIFrame = document.createElement("iframe");
            hostCommIFrame.id = hostCommIFrame.name = HOST_COMM_IFRAME_NAME;
            base_host_location = hostCommIFrame.src = fp.urls.constructHostCommFallback();
            hostCommIFrame.style.display = 'none';
            var onload = function(){
                base_host_location = hostCommIFrame.contentWindow.location.href;
                //Then we open the filepicker comm iframe
                openFPCommIframe();
            };
            if (hostCommIFrame.attachEvent) {
                hostCommIFrame.attachEvent('onload', onload);
            } else {
                hostCommIFrame.onload = onload;
            }
            document.body.appendChild(hostCommIFrame);
        }
    };

    var openFPCommIframe = function(){
        if (window.frames[FP_COMM_IFRAME_NAME] === undefined) {
            //Opening an iframe to send events
            var fpCommIFrame;
            fpCommIFrame = document.createElement("iframe");
            fpCommIFrame.id = fpCommIFrame.name = FP_COMM_IFRAME_NAME;
            fpCommIFrame.src = fp.urls.FP_COMM_FALLBACK + "?host_url=" + encodeURIComponent(base_host_location);
            fpCommIFrame.style.display = 'none';
            document.body.appendChild(fpCommIFrame);
        }
        openCommunicationsChannel();
    };

    /*
     * 1. Creates the general communcation handler
     * 2. Set to listen
     * ONLY RUN ONCE
     */
    var isOpen = false;
    var timer = undefined;
    var lastHash = "";
    var checkHash = function(){
        var comm_iframe = window.frames[FP_COMM_IFRAME_NAME];
        if (!comm_iframe) {return;}
        var host_iframe = comm_iframe.frames[HOST_COMM_IFRAME_NAME];
        if (!host_iframe) {return;}

        var hash = host_iframe.location.hash;
        //sanitization
        if (hash && hash.charAt(0) == "#") {
            hash = hash.substr(1);
        }
        if (hash === lastHash) {return;}
        lastHash = hash;
        if (!lastHash) {return;}

        var data;
        try{
            data = fp.json.parse(hash);
        } catch (e){}

        if (data) {
            fp.handlers.run(data);
        }
    };

    var openCommunicationsChannel = function(){
        if (isOpen){
            return;
        } else {
            isOpen = true;
        }

        timer = window.setInterval(checkHash, hash_check_interval);
    };

    var destroyCommIframe = function(){
        window.clearInterval(timer);

        if (!isOpen){
            return;
        } else {
            isOpen = false;
        }
        //Also removing iframe
        var iframes = document.getElementsByName(FP_COMM_IFRAME_NAME);
        for (var i = 0; i < iframes.length; i++){
            iframes[i].parentNode.removeChild(iframes[i]);
        }
        try{delete window.frames[FP_COMM_IFRAME_NAME];}catch(e){}

        iframes = document.getElementsByName(HOST_COMM_IFRAME_NAME);
        for (i = 0; i < iframes.length; i++){
            iframes[i].parentNode.removeChild(iframes[i]);
        }
        try{delete window.frames[HOST_COMM_IFRAME_NAME];}catch(e){}
    };

    var isEnabled = !('postMessage' in window);
    var setEnabled = function(enabled) {
        if (enabled !== isEnabled) {
            isEnabled = !!enabled;
            if (isEnabled) {
                activate();
            } else {
                deactivate();
            }
        }
    };

    var old_comm;
    var activate = function(){
        old_comm = fp.comm;
        fp.comm = {
            openChannel: openCommIframe,
            closeChannel: destroyCommIframe
        };
    };

    var deactivate = function(){
        fp.comm = old_comm;
        old_comm = undefined;
    };

    if (isEnabled) {
        activate();
    }

    return {
        openChannel: openCommIframe,
        closeChannel: destroyCommIframe,
        isEnabled: isEnabled
    };
});
//conversions.js
filepicker.extend("conversions", function(){
    var fp = this;

    var valid_parameters = {
        width: 'number',
        height: 'number',
        fit: 'string',
        format: 'string',
        watermark: 'string',
        watermark_size: 'number',
        watermark_position: 'string',
        align: 'string',
        crop: 'string or array',
        quality: 'number',
        text: 'string',
        text_font: 'string',
        text_size: 'number',
        text_color: 'string',
        text_align: 'string',
        text_padding: 'number',
        policy: 'string',
        signature: 'string',
        storeLocation: 'string',
        storePath: 'string',
        storeContainer: 'string',
        storeAccess: 'string',
        rotate: 'string or number'
    };

    var checkParameters = function(options) {
        var found;
        for (var key in options) {
            found = false;
            for (var test in valid_parameters) {
                if (key == test) {
                    found = true;
                    if (valid_parameters[test].indexOf(fp.util.typeOf(options[key])) === -1) {
                        throw new fp.FilepickerException("Conversion parameter "+key+" is not the right type: "+options[key]+". Should be a "+valid_parameters[test]);
                    }
                }
            }
            if (!found) {
                throw new fp.FilepickerException("Conversion parameter "+key+" is not a valid parameter.");
            }
        }
    };

    var convert = function(fp_url, options, onSuccess, onError, onProgress){
        checkParameters(options);

        if (options.crop && fp.util.isArray(options.crop)) {
            options.crop = options.crop.join(",");
        }

        fp.ajax.post(fp_url+'/convert', {
            data: options,
            json: true,
            success: function(fpfile) {
                onSuccess(fp.util.standardizeFPFile(fpfile));
            },
            error: function(msg, status, xhr) {
                if (msg == "not_found") {
                    onError(new fp.errors.FPError(141));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(142));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(143));
                }
            },
            progress: onProgress
        });
    };

    return {
        convert: convert
    };
});
//cookies.js
filepicker.extend("cookies", function(){
    var fp = this;

    var getReceiveCookiesMessage = function(callback) {
        var handler = function(data) {            
            if (data.type !== "ThirdPartyCookies"){
                return;
            }
            fp.cookies.THIRD_PARTY_COOKIES = !!data.payload;
            if (callback && typeof callback === "function"){ callback(!!data.payload);}
        };
        return handler;
    };

    var checkThirdParty = function(callback) {
        var handler = getReceiveCookiesMessage(callback);
        fp.handlers.attach('cookies', handler);

        fp.comm.openChannel();
    };

    return {
        checkThirdParty: checkThirdParty
    };
});
//dragdrop.js
filepicker.extend("dragdrop", function(){
    var fp = this;

    var canDragDrop = function(){
        return (!!window.FileReader || navigator.userAgent.indexOf("Safari") >= 0) && 
        ('draggable' in document.createElement('span'));
    };

    //Takes the passed in div and makes it into a drop pane
    //options: multiple, mimetype, extension, maxSize
    //dragEnter, dragLeave
    //onStart, onSuccess, onError, onProgress
    var makeDropPane = function(div, options) {
        var err = "No DOM element found to create drop pane";
        if (!div) {
            throw new fp.FilepickerException(err);
        }
        if (div.jquery) {
            if (div.length === 0) {
                throw new fp.FilepickerException(err);
            }
            div = div[0];
        }

        if (!canDragDrop()) {
            fp.util.console.error("Your browser doesn't support drag-drop functionality");
            return false;
        }

        options = options || {};
        //setting up defaults
        var dragEnter = options['dragEnter'] || function(){};
        var dragLeave = options['dragLeave'] || function(){};
        var onStart = options['onStart'] || function(){};
        var onSuccess = options['onSuccess'] || function(){};
        var onError = options['onError'] || function(){};
        var onProgress = options['onProgress'] || function(){};

        var mimetypes = options['mimetypes'];
        if (!mimetypes) {
            if (options['mimetype']) {
                mimetypes = [options['mimetype']];
            } else {
                mimetypes = ["*/*"];
            }
        }

        if (fp.util.typeOf(mimetypes) == 'string'){
            mimetypes = mimetypes.split(',');
        }

        var extensions = options['extensions'];
        if (!extensions) {
            if (options['extension']) {
                extensions = [options['extensions']];
            }
        }

        if (fp.util.typeOf(extensions) == 'string'){
            extensions = extensions.split(',');
        }

        var store_options = {
            location: options['location'],
            path: options['path'],
            container: options['container'],
            access: options['access'],
            policy: options['policy'],
            signature: options['signature']
        };

        var enabled = function() {
            return div && (div.getAttribute("disabled") || "enabled") != "disabled";
        };

        //event listeners
        div.addEventListener("dragenter", function(e){
            if (enabled()) {
                dragEnter();
            }

            e.stopPropagation();
            e.preventDefault();
            return false;
        }, false);

        div.addEventListener("dragleave", function(e){
            if (enabled()) {
                dragLeave();
            }

            e.stopPropagation();
            e.preventDefault();
            return false;
        }, false);

        div.addEventListener("dragover", function(e) {
            e.preventDefault();
            return false;
        }, false);

        div.addEventListener("drop", function(e) {
            e.stopPropagation();
                e.preventDefault();

            if (!enabled()) { return false; }

            //check for folders
            var i; var items; var entry;
            if (e.dataTransfer.items) {
                items = e.dataTransfer.items;
                for (i = 0; i < items.length; i++) {
                    entry = items[i] && items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : undefined;

                    if (entry && !!entry.isDirectory) {
                        onError("WrongType", "Uploading a folder is not allowed");
                        return false;
                    }
                }
            }

            var files = e.dataTransfer.files;
            var total = files.length;
            if (verifyUpload(files)) {
                onStart(files);
                //disabling
                div.setAttribute("disabled", "disabled");
                for (i = 0; i < files.length; i++) {
                    fp.store(files[i], store_options, getSuccessHandler(i, total), errorHandler, getProgressHandler(i, total));
                }
            }
            return false;
        });

        var progresses = {};
        var response = [];
        var getSuccessHandler = function(i, total) {
            return function(fpfile) {
                if (!options['multiple']) {
                    onSuccess([fpfile]);
                } else {
                    response.push(fpfile);
                    if (response.length == total) {
                        onSuccess(response);
                        response = [];
                        progresses = {};
                        //Re-enabling
                        div.setAttribute("disabled", "enabled");
                    } else {
                        progresses[i] = 100;
                        updateProgress(total);
                    }
                }
            };
        };

        var errorHandler = function(err) {
            onError("UploadError", err.toString());
        };

        var getProgressHandler = function(i, total) {
            return function(percent) {
                progresses[i] = percent;
                updateProgress(total);
            };
        };

        var updateProgress = function(totalCount){
            var totalProgress = 0;
            for (var i in progresses) {
                totalProgress += progresses[i];
            }
            var percentage = totalProgress / totalCount;
            onProgress(percentage);
        };

        var verifyUpload = function(files) {
            if (files.length > 0 ) {
                //Verify number
                if (files.length > 1 && !options['multiple']) {
                    onError("TooManyFiles", "Only one file at a time");
                    return false;
                }
                //Verify against extension, mimetypes, size
                var found; var file; var filename;
                for (var i = 0; i < files.length; i++) {
                    found = false;
                    file = files[i];
                    filename = file.name || file.fileName || '"Unknown file"';
                    for (var j = 0; j < mimetypes.length; j++) {
                        var mimetype = fp.mimetypes.getMimetype(file);
                        found = found || fp.mimetypes.matchesMimetype(mimetype, mimetypes[j]);
                    }

                    if (!found) {
                        onError("WrongType", filename + " isn't the right type of file");
                        return false;
                    }

                    if (extensions) {
                        found = false;
                        for (j = 0; j < extensions.length; j++) {
                            found = found || fp.util.endsWith(filename, extensions[j]);
                        }

                        if (!found) {
                            onError("WrongType", filename + " isn't the right type of file");
                            return false;
                        }
                    }

                    if (file.size && !!options.maxSize && file.size > options.maxSize) {
                        onError("WrongSize", filename + " is too large ("+file.size+" Bytes)");
                        return false;
                    }
                }
                //we're all good
                return true;
            } else {
                onError("NoFilesFound", "No files uploaded");
            }
            return false;
        };

        return true;
    };

    return {
        enabled: canDragDrop,
        makeDropPane: makeDropPane
    };
});
//errors.js
filepicker.extend("errors", function(){
    var fp = this;

    var FPError = function(code) {
        if (this === window) { return new FPError(code);}

        this.code = code;
        if (filepicker.debug) {
            var info = filepicker.error_map[this.code];
            this.message = info.message;
            this.moreInfo = info.moreInfo;
            this.toString = function(){
                return "FPError "+this.code+": "+this.message+". For help, see "+this.moreInfo;
            };
        } else {
            this.toString = function(){return "FPError "+this.code+". Include filepicker_debug.js for more info";};
        }
        return this;
    };
    //Telling router how to call us
    FPError.isClass = true;

    //The defualt error handler
    var handleError = function(fperror) {
        if (filepicker.debug) {
            fp.util.console.error(fperror.toString());
        }
    };

    return {
        FPError: FPError,
        handleError: handleError
    };
}, true);
//exporter.js
filepicker.extend("exporter", function(){
    var fp = this;

    var normalizeOptions = function(options) {
        var normalize = function(singular, plural, def){
            if (options[plural] && !fp.util.isArray(options[plural])) {
                options[plural] = [options[plural]];
            } else if (options[singular]) {
                options[plural] = [options[singular]];
            } else if (def) {
                options[plural] = def;
            }
        };

        if (options['mimetype'] && options['extension']) {
            throw fp.FilepickerException("Error: Cannot pass in both mimetype and extension parameters to the export function");
        }
        normalize('service', 'services');
        if (options['services']) {
            for (var i = 0; i < options['services'].length; i++) {
                var service = (''+options['services'][i]).replace(" ","");
                var sid = fp.services[service];
                options['services'][i] = (sid === undefined ? service : sid);
            }
        }
        if (options['openTo']) {
            options['openTo'] = fp.services[options['openTo']] || options['openTo'];
        }

        fp.util.setDefault(options, 'container', 'modal');
    };

    var getExportHandler = function(onSuccess, onError) {
        var handler = function(data) {
            if (data.type !== "filepickerUrl"){
                return;
            }

            if (data.error) {
                fp.util.console.error(data.error);
                onError(fp.errors.FPError(132));
            } else {
                var fpfile = {};
                //TODO: change payload to not require parsing
                fpfile.url = data.payload.url;
                fpfile.filename = data.payload.data.filename;
                fpfile.mimetype = data.payload.data.type;
                fpfile.size = data.payload.data.size;
                //TODO: get writeable
                fpfile.isWriteable = true;
                onSuccess(fpfile);
            }

            //Try to close a modal if it exists.
            fp.modal.close();
        };
        return handler;
    };

    var createExporter = function(input, options, onSuccess, onError) {
        normalizeOptions(options);

        if (options['debug']) {
            //return immediately, but still async
            setTimeout(function(){
                onSuccess({
                    url: "http://www.local-fp.com/api/file/-nBq2onTSemLBxlcBWn1",
                    filename: 'test.png',
                    mimetype: 'image/png',
                    size:58979
                });
            }, 1);
            return;
        }

        if (fp.cookies.THIRD_PARTY_COOKIES === undefined) {
            //if you want a modal, then we need to wait until we know if 3rd party cookies allowed.
            fp.cookies.checkThirdParty(function(){
                createExporter(input, options, onSuccess, onError);
            });
            return;
        }

        var id = fp.util.getId();
        
        //Wrapper around on success to make sure we don't also fire on close
        var finished = false;
        var onSuccessMark = function(fpfile){
            finished = true;
            onSuccess(fpfile);
        };
        var onErrorMark = function(fperror){
            finished = true;
            onError(fperror);
        };

        var onClose = function(){
            if (!finished) {
                finished = true;
                onError(fp.errors.FPError(131));
            }
        };

        if (options['container'] == 'modal' && (options['mobile'] || fp.window.shouldForce())) {
            options['container'] = 'window';
        }

        fp.window.open(options['container'], fp.urls.constructExportUrl(input, options, id), onClose);
        fp.handlers.attach(id, getExportHandler(onSuccessMark, onErrorMark));
    };

    return {
        createExporter: createExporter
    };
});
//files.js
filepicker.extend("files", function(){
    var fp = this;

    var readFromFPUrl = function(url, options, onSuccess, onError, onProgress){
        //If base64encode === true, then we get base64 back from the server and pass it back
        //If base64encode === false, then we pass back what we get from the server
        //If it's not specified, we do the thing most likely to be right, which is to ask for it base64
        //encoded from the server and decode it before giving it back
        var temp64 = options.base64encode === undefined;
        if (temp64) {
            options.base64encode = true;
        }
        options['base64encode'] = options['base64encode'] !== false;

        var success = function(responseText) {
            if (temp64) {
                responseText = fp.base64.decode(responseText, !!options['asText']);
            }
            onSuccess(responseText);
        };

        readFromUrl.call(this, url, options, success, onError, onProgress);
    };

    var readFromUrl = function(url, options, onSuccess, onError, onProgress){

        if (options['cache'] !== true) {
            options['_cacheBust'] = fp.util.getId();
        }

        fp.ajax.get(url, {
            data: options,
            headers: {'X-NO-STREAM': true},
            success: onSuccess,
            error: function(msg, status, xhr) {
                if (msg == "CORS_not_allowed") {
                    onError(new fp.errors.FPError(113));
                } else if (msg == "CORS_error") {
                    onError(new fp.errors.FPError(114));
                } else if (msg == "not_found") {
                    onError(new fp.errors.FPError(115));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(400));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(118));
                }
            },
            progress: onProgress
        });
    };

    var readFromFile = function(file, options, onSuccess, onError, onProgress){
        if (!(window.File && window.FileReader && window.FileList && window.Blob)) {
            //Browser doesn't support reading from DOM file objects, so store the file and read from there
            onProgress(10);
            fp.files.storeFile(file, {}, function(fpfile){
                onProgress(50);
                fp.files.readFromFPUrl(fpfile.url, options, onSuccess, onError,
                    function(progress){
                        onProgress(50+progress/2);
                    });
            }, onError, function(progress){
                onProgress(progress/2);
            });

            //Lame way - error out
            //onError(new fp.errors.FPError(111));
            return;
        }

        var base64encode = !!options['base64encode'];
        var asText = !!options['asText'];

        var reader = new FileReader();

        reader.onprogress = function(evt) {
            if (evt.lengthComputable) {
                onProgress(Math.round((evt.loaded/evt.total) * 100));
            }
        };

        reader.onload = function(evt) {
            onProgress(100);
            if (base64encode) {
                //asText determines whether we utf8encode or not
                onSuccess(fp.base64.encode(evt.target.result, asText));
            } else {
                onSuccess(evt.target.result);
            }
        };

        reader.onerror = function(evt) {
            switch(evt.target.error.code) {
                case evt.target.error.NOT_FOUND_ERR:
                    onError(new fp.errors.FPError(115));
                    break;
                case evt.target.error.NOT_READABLE_ERR:
                    onError(new fp.errors.FPError(116));
                    break;
                case evt.target.error.ABORT_ERR:
                    onError(new fp.errors.FPError(117));
                    break; // noop
                default:
                    onError(new fp.errors.FPError(118));
                    break;
            }
        };

        //TODO: For IE10, use readAsArrayBuffer, handle result
        if (asText || !reader.readAsBinaryString) {
            reader.readAsText(file);
        } else {
            reader.readAsBinaryString(file);
        }
    };

    var writeDataToFPUrl = function(fp_url, input, options, onSuccess, onError, onProgress) {
        var mimetype = options['mimetype'] || 'text/plain';
        fp.ajax.post(fp.urls.constructWriteUrl(fp_url, options), {
            headers: {'Content-Type': mimetype},
            data: input,
            processData: false,
            json: true,
            success: function(json) {
                onSuccess(fp.util.standardizeFPFile(json));
            },
            error: function(msg, status, xhr) {
                if (msg == "not_found") {
                    onError(new fp.errors.FPError(121));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(122));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(123));
                }
            },
            progress: onProgress
        });
    };

    var writeFileInputToFPUrl = function(fp_url, input, options, onSuccess, onError, onProgress) {
        var error = function(msg, status, xhr) {
            if (msg == "not_found") {
                onError(new fp.errors.FPError(121));
            } else if (msg == "bad_params") {
                onError(new fp.errors.FPError(122));
            } else if (msg == "not_authorized") {
                onError(new fp.errors.FPError(403));
            } else {
                onError(new fp.errors.FPError(123));
            }
        };
        var success = function(json) {
            onSuccess(fp.util.standardizeFPFile(json));
        };

        uploadFile(input, fp.urls.constructWriteUrl(fp_url, options), success, error, onProgress);
    };

    var writeFileToFPUrl = function(fp_url, input, options, onSuccess, onError, onProgress) {
        var error = function(msg, status, xhr) {
            if (msg == "not_found") {
                onError(new fp.errors.FPError(121));
            } else if (msg == "bad_params") {
                onError(new fp.errors.FPError(122));
            } else if (msg == "not_authorized") {
                onError(new fp.errors.FPError(403));
            } else {
                onError(new fp.errors.FPError(123));
            }
        };
        var success = function(json) {
            onSuccess(fp.util.standardizeFPFile(json));
        };

        options['mimetype'] = input.type;

        uploadFile(input, fp.urls.constructWriteUrl(fp_url, options), success, error, onProgress);
    };

    var writeUrlToFPUrl = function(fp_url, input, options, onSuccess, onError, onProgress) {
        fp.ajax.post(fp.urls.constructWriteUrl(fp_url, options), {
            data: {'url': input},
            json: true,
            success: function(json) {
                onSuccess(fp.util.standardizeFPFile(json));
            },
            error: function(msg, status, xhr) {
                if (msg == "not_found") {
                    onError(new fp.errors.FPError(121));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(122));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(123));
                }
            },
            progress: onProgress
        });
    };

    var storeFileInput = function(input, options, onSuccess, onError, onProgress) {
        //Not sure why we're here if we have a files object, just do that
        if (input.files) {
            if (input.files.length === 0) {
                onError(new fp.errors.FPError(115));
            } else {
                storeFile(input.files[0], options, onSuccess, onError, onProgress);
            }
            return;
        }

        fp.util.setDefault(options, 'location', 'S3');

        if (!options['filename']) {
            options['filename'] = input.value.replace("C:\\fakepath\\","") || input.name;
        }

        var old_name = input.name;
        input.name = "fileUpload";
        fp.iframeAjax.post(fp.urls.constructStoreUrl(options), {
            //data: {'fileUpload': input},
            data: input,
            processData: false,
            json: true,
            success: function(json) {
                input.name = old_name;
                //Massaging the response - we want a mimetype for fpfiles not a type
                onSuccess(fp.util.standardizeFPFile(json));
            },
            error: function(msg, status, xhr) {
                if (msg == "not_found") {
                    onError(new fp.errors.FPError(121));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(122));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(123));
                }
            }
        });
    };
        
    //Takes a file and hands back a url
    var storeFile = function(input, options, onSuccess, onError, onProgress) {
        fp.util.setDefault(options, 'location', 'S3');

        var error = function(msg, status, xhr) {
            if (msg == "not_found") {
                onError(new fp.errors.FPError(121));
            } else if (msg == "bad_params") {
                onError(new fp.errors.FPError(122));
            } else if (msg == "not_authorized") {
                onError(new fp.errors.FPError(403));
            } else {
                fp.util.console.error(msg);
                onError(new fp.errors.FPError(123));
            }
        };
        var success = function(json) {
            //Massaging the response - we want a mimetype for fpfiles not a type
            onSuccess(fp.util.standardizeFPFile(json));
        };

        if (!options['filename']) {
            options['filename'] = input.name || input.fileName;
        }

        uploadFile(input, fp.urls.constructStoreUrl(options), success, error, onProgress);
    };

    var uploadFile = function(file, url, success, error, progress) {
        if (file.files) {
            file = file.files[0];
        }
        var html5Upload = !!window.FormData && !!window.XMLHttpRequest;
        if (html5Upload) {
            data = new FormData();
            data.append('fileUpload',file);
            fp.ajax.post(url, {
                json: true,
                processData: false,
                data: data,
                success: success,
                error: error,
                progress: progress
            });
        } else {
            fp.iframeAjax.post(url, {
                data: file,
                json: true,
                success: success,
                error: error
            });
        }
    };

    var storeData = function(input, options, onSuccess, onError, onProgress) {
        fp.util.setDefault(options, 'location', 'S3');
        fp.util.setDefault(options, 'mimetype', 'text/plain');
        
        fp.ajax.post(fp.urls.constructStoreUrl(options), {
            headers: {'Content-Type': options['mimetype']},
            data: input,
            processData: false,
            json: true,
            success: function(json) {
                //Massaging the response - we want a mimetype for fpfiles not a type
                onSuccess(fp.util.standardizeFPFile(json));
            },
            error: function(msg, status, xhr) {
                if (msg == "not_found") {
                    onError(new fp.errors.FPError(121));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(122));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(123));
                }
            },
            progress: onProgress
        });
    };

    var storeUrl = function(input, options, onSuccess, onError, onProgress) {
        fp.util.setDefault(options, 'location', 'S3');

        fp.ajax.post(fp.urls.constructStoreUrl(options), {
            data: {'url': input},
            json: true,
            success: function(json) {
                //Massaging the response - we want a mimetype for fpfiles not a type
                onSuccess(fp.util.standardizeFPFile(json));
            },
            error: function(msg, status, xhr) {
                if (msg == "not_found") {
                    onError(new fp.errors.FPError(151));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(152));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(153));
                }
            },
            progress: onProgress
        });
    };

    var stat = function(fp_url, options, onSuccess, onError) {
        var dateparams = ['uploaded','modified','created'];

        if (options['cache'] !== true) {
            options['_cacheBust'] = fp.util.getId();
        }

        fp.ajax.get(fp_url+"/metadata", {
            json: true,
            data: options,
            success: function(metadata) {
                for (var i = 0; i < dateparams.length; i++) {
                    if (metadata[dateparams[i]]) {
                        metadata[dateparams[i]] = new Date(metadata[dateparams[i]]);
                    }
                }
                onSuccess(metadata);
            },
            error: function(msg, status, xhr) {
                if (msg == "not_found") {
                    onError(new fp.errors.FPError(161));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(400));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(162));
                }
            }
        });
    };

    var remove = function(fp_url, options, onSuccess, onError) {
        options['key'] = fp.apikey;
        fp.ajax.post(fp_url+"/remove", {
            data: options,
            success: function(resp) {
                onSuccess();
            },
            error: function(msg, status, xhr) {
                if (msg == "not_found") {
                    onError(new fp.errors.FPError(171));
                } else if (msg == "bad_params") {
                    onError(new fp.errors.FPError(400));
                } else if (msg == "not_authorized") {
                    onError(new fp.errors.FPError(403));
                } else {
                    onError(new fp.errors.FPError(172));
                }
            }
        });
    };

    return {
        readFromUrl: readFromUrl,
        readFromFile: readFromFile,
        readFromFPUrl: readFromFPUrl,
        writeDataToFPUrl: writeDataToFPUrl,
        writeFileToFPUrl: writeFileToFPUrl,
        writeFileInputToFPUrl: writeFileInputToFPUrl,
        writeUrlToFPUrl: writeUrlToFPUrl,
        storeFileInput: storeFileInput,
        storeFile: storeFile,
        storeUrl: storeUrl,
        storeData: storeData,
        stat: stat,
        remove: remove
    };
});
//handlers.js
filepicker.extend("handlers", function(){
    var fp = this;
    var storage = {};

    var attachHandler = function(id, handler){
        if (storage.hasOwnProperty(id)){ 
            storage[id].push(handler);
        } else {
            storage[id] = [handler];
        }
        return handler;
    };

    var detachHandler = function(id, fn){
        var handlers = storage[id];
        if (!handlers) {
            return;
        }

        if (fn) {
            for (var i = 0; i < handlers.length; i++) {
                if (handlers[i] === fn) {
                    handlers.splice(i,1);
                    break;
                }
            }
            if (handlers.length === 0) {
                delete(storage[id]);
            }
        } else {
            delete(storage[id]);
        }
    };

    var run = function(data){
        var callerId = data.id;
        if (storage.hasOwnProperty(callerId)){ 
            //have to grab first in case someone removes mid-go
            var handlers = storage[callerId];
            for (var i = 0; i < handlers.length; i++) {
                handlers[i](data);
            }
            return true;
        }
        return false;
    };

    return {
        attach: attachHandler,
        detach: detachHandler,
        run: run
    };
});
//iframeAjax.js
filepicker.extend("iframeAjax", function(){
    var fp = this;

    var IFRAME_ID = "ajax_iframe";

    //we can only have one out at a time
    var queue = [];
    var running = false;

    var get_request = function(url, options) {
        options['method'] = 'GET';
        make_request(url, options);
    };

    var post_request = function(url, options) {
        options['method'] = 'POST';
        url += (url.indexOf('?') >= 0 ? '&' : '?') + '_cacheBust='+fp.util.getId();
        make_request(url, options);
    };

    var runQueue = function(){
        if (queue.length > 0) {
            var next = queue.shift();
            make_request(next.url, next.options);
        }
    };

    //Take the data, wrap it in an input and a form, submit that into an iframe, and get the response
    var make_request = function(url, options) {
        if (running) {
            queue.push({url: url, options: options});
            return;
        }

        url += (url.indexOf('?') >= 0 ? '&' : '?') + '_cacheBust='+fp.util.getId();
        url += "&Content-Type=text%2Fhtml";

        fp.comm.openChannel();

        //Opening an iframe to make the request to
        var uploadIFrame;
        //IE makes us do rediculous things -
        //http://terminalapp.net/submitting-a-form-with-target-set-to-a-script-generated-iframe-on-ie/
        try {
          uploadIFrame = document.createElement('<iframe name="'+IFRAME_ID+'">');
        } catch (ex) {
          uploadIFrame = document.createElement('iframe');
        }
        uploadIFrame.id = uploadIFrame.name = IFRAME_ID;
        uploadIFrame.style.display = 'none';
        var release = function(){
            //so we don't lock ourselves
            running = false;
        };
        if (uploadIFrame.attachEvent) {
            uploadIFrame.attachEvent("onload", release);
            uploadIFrame.attachEvent("onerror", release);
        } else {
            uploadIFrame.onerror = uploadIFrame.onload = release;
        }

        uploadIFrame.id = IFRAME_ID;
        uploadIFrame.name = IFRAME_ID;
        uploadIFrame.style.display = 'none';
        uploadIFrame.onerror = uploadIFrame.onload = function(){
            //so we don't lock ourselves
            running = false;
        };
        document.body.appendChild(uploadIFrame);

        fp.handlers.attach('upload', getReceiveUploadMessage(options));
        var form = document.createElement("form");
        form.method = options['method'] || 'GET';
        form.action = url;
        form.target = IFRAME_ID;
        
        var data = options['data'];
        if (fp.util.isFileInputElement(data) || fp.util.isFile(data)) {
            //For IE8 you need both. Obnoxious
            form.encoding = form.enctype = "multipart/form-data";
        }

        document.body.appendChild(form);

        //For the data: if it's an input already, put that in the form
        //If it's a File object, we have to get tricky and find the input
        //otherwise we just create the input
        if (fp.util.isFile(data)) {
            var file_input = getInputForFile(data);
            if (!file_input) {
                throw fp.FilepickerException("Couldn't find corresponding file input.");
            }
            //key: val
            data = {'fileUpload': file_input};
        } else if (fp.util.isFileInputElement(data)) {
            var input = data;
            data = {};
            data['fileUpload'] = input;
        } else if (data && fp.util.isElement(data) && data.tagName == "INPUT") {
            input = data;
            data = {};
            data[input.name] = input;
        } else if (options.processData !== false) {
            data = {'data': data};
        }

        data['format'] = 'iframe';

        var input_cache = {};
        for (var key in data) {
            var val = data[key];
            if (fp.util.isElement(val) && val.tagName == "INPUT") {
                input_cache[key] = {
                    par: val.parentNode,
                    sib: val.nextSibling,
                    name: val.name,
                    input: val,
                    focused: val == document.activeElement
                };
                val.name = key;
                form.appendChild(val);
            } else {
                var input_val = document.createElement("input");
                input_val.name = key;
                input_val.value = val;
                form.appendChild(input_val);
            }
        }

        running = true;

        //pulling this into a different thread to prevent timing weirdness
        window.setTimeout(function(){
            form.submit();

            //Now we put everything back
            for (var cache_key in input_cache) {
                var cache_val = input_cache[cache_key];
                cache_val.par.insertBefore(cache_val.input, cache_val.sib);
                cache_val.input.name = cache_val.name;
                if (cache_val.focused) {
                    cache_val.input.focus();
                }
            }
            form.parentNode.removeChild(form);
        }, 1);
    };

    var getReceiveUploadMessage = function(options) {
        var success = options['success'] || function(){};
        var error = options['error'] || function(){};
        var handler = function(data) {            
            if (data.type !== "Upload"){
                return;
            }
            running = false;
            var response = data.payload;
            if (response['error']) {
                error(response['error']);
            } else {
                success(response);
            } 
            //So we don't double-call in the future
            fp.handlers.detach("upload");
            runQueue();
        };
        return handler;
    };

    var getInputForFile = function(file) {
        //probably won't be _that_ slow because there aren't usually many inputs/page
        var inputs = document.getElementsByTagName("input");
        for (var i = 0; i < inputs.length; i++) {
            var input = inputs[0];
            if (input.type != "file" || !input.files || !input.files.length) {
                continue;
            }
            for (var j = 0; j < input.files.length; j++) {
                if (input.files[j] === file) {
                    return input;
                }
            }
        }
        return null;
    };

    return {
        get: get_request,
        post: post_request,
        request: make_request
    };
});
filepicker.extend("json", function(){
    var fp = this;

    var special = {'\b': '\\b', '\t': '\\t', '\n': '\\n', '\f': '\\f', '\r': '\\r', '"' : '\\"', '\\': '\\\\'};

    var escape = function(chr){
        return special[chr] || '\\u' + ('0000' + chr.charCodeAt(0).toString(16)).slice(-4);
    };

    var validate = function(string){
        string = string.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, '@').
                        replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, ']').
                        replace(/(?:^|:|,)(?:\s*\[)+/g, '');

        return (/^[\],:{}\s]*$/).test(string);
    };

    var encode = function(obj) {
        if (window.JSON && window.JSON.stringify) {
            return window.JSON.stringify(obj);
        }
        if (obj && obj.toJSON) obj = obj.toJSON();

        var string = [];
        switch (fp.util.typeOf(obj)){
            case 'string':
                return '"' + obj.replace(/[\x00-\x1f\\"]/g, escape) + '"';
            case 'array':
                for (var i = 0; i < obj.length; i++) {
                    string.push(encode(obj[i]));
                }
                return '[' + string + ']';
            case 'object': case 'hash':
                var json;
                var key;
                for (key in obj) {
                    json = encode(obj[key]);
                    if (json) string.push(encode(key) + ':' + json);
                    json = null;
                }
                return '{' + string + '}';
            case 'number': case 'boolean': return '' + obj;
            case 'null': return 'null';
            default: return 'null';
        }

        return null;
    };

    var decode = function(string, secure){
        if (!string || fp.util.typeOf(string) != 'string') return null;

        if (window.JSON && window.JSON.parse) {
            return window.JSON.parse(string);
        } else {
            if (secure){
                if (!validate(string)) throw new Error('JSON could not decode the input; security is enabled and the value is not secure.');
            }
            return eval('(' + string + ')');
        }
    };

    return {
        validate: validate,
        encode: encode,
        stringify: encode,
        decode: decode,
        parse: decode
    };
});
//lib.js
filepicker.extend(function(){
    var fp = this;
    fp.API_VERSION = "v1";

    var setKey = function(key) {
        fp.apikey = key;
    };

    var FilepickerException = function(text){
        this.text = text;
        this.toString = function(){return "FilepickerException: "+this.text;};
        return this;
    };
    //Telling router how to call us
    FilepickerException.isClass = true;

    var checkApiKey = function(){
        if (!fp.apikey) {
            throw new fp.FilepickerException("API Key not found");
        }
    };

    /**
     * Pops open the filepicker.io picker dialog to select a single file.
     * Arguments:
     * options: @Object. Optional. Key-value pairs to tweak how the dialog looks and behaves. Valid options:
     *   service: @ServiceEnum: the service to pick from
     *   services: @Array[@ServiceEnum]: the services to pick from
     *   openTo: @ServiceEnum: the service to start on
     *   container: @String: either "window", "modal", or the id of the iframe to open in
     *   mimetype: @String: only allow picking files of the specified mimetype
     *   mimetypes: @Array[@String]: only allow picking files of the specified mimetypes
     *   extension: @String: only allow picking files of the specified extension
     *   extensions: @Array[@String]: only allow picking files of the specified extensions
     *   maxSize: @Number: only allow picking files below the specified size
     *   debug: @Boolean: If true, returns immediately with dummy data
     * onSuccess: @Function(@FPFile). Function called when a file is picked successfully
     * onError: @Function(@FPError). Function called when there is an error picking a file. Errors:
     *   101: The user closed the picker without choosing a file
     *   102: Unknown error in picking file
     */
    var pick = function(options, onSuccess, onError) {
        checkApiKey();

        if (typeof options === "function") {
            //Shift left
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }

        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;

        fp.picker.createPicker(options, onSuccess, onError, false);
    };
    
    /**
     * Pops open the filepicker.io picker dialog to select multiple files.
     * Arguments:
     * options: @Object. Optional. Key-value pairs to tweak how the dialog looks and behaves. Valid options:
     *   service: @ServiceEnum: the service to pick from
     *   services: @Array[@ServiceEnum]: the services to pick from
     *   openTo: @ServiceEnum: the service to start on
     *   container: @String: either "window", "modal", or the id of the iframe to open in
     *   mimetype: @String: only allow picking files of the specified mimetype
     *   mimetypes: @Array[@String]: only allow picking files of the specified mimetypes
     *   extension: @String: only allow picking files of the specified extension
     *   extensions: @Array[@String]: only allow picking files of the specified extensions
     *   maxSize: @Number: only allow picking files below the specified size
     *   maxFiles: @Number: only allowing picking a max of N files at a time
     *   folders: @Boolean: allow entire folders to be uploaded
     *   debug: @Boolean: If true, returns immediately with dummy data
     * onSuccess: @Function(@Array[@FPFile]). Function called when one or more files is picked successfully
     * onError: @Function(@FPError). Function called when there is an error picking files. Errors:
     *   101: The user closed the picker without choosing any file
     *   102: Unknown error in picking file
     */
    var pickMultiple = function(options, onSuccess, onError, onProgress) {
        checkApiKey();

        if (typeof options === "function") {
            //Shift left
            onProgress = onError;
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }

        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;

        fp.picker.createPicker(options, onSuccess, onError, true, false, onProgress);
    };

    /**
     * Pops open the filepicker.io picker dialog to select files and store them.
     * Arguments:
     * picker_options: @Object. Key-value pairs to tweak how the dialog looks and behaves. Valid options:
     *   multiple: @Boolean: whether to allow multiple files
     *   service: @ServiceEnum: the service to pick from
     *   services: @Array[@ServiceEnum]: the services to pick from
     *   openTo: @ServiceEnum: the service to start on
     *   container: @String: either "window", "modal", or the id of the iframe to open in
     *   mimetype: @String: only allow picking files of the specified mimetype
     *   mimetypes: @Array[@String]: only allow picking files of the specified mimetypes
     *   extension: @String: only allow picking files of the specified extension
     *   extensions: @Array[@String]: only allow picking files of the specified extensions
     *   maxSize: @Number: only allow picking files below the specified size
     *   debug: @Boolean: If true, returns immediately with dummy data
     * store_options: @Object. Key-value pairs to tweak how the file is stored. Valid options:
     *   location: @LocationEnum: the location to store the data in.
     *   path: @String: the path to store the data in.
     *   container: @String: the container to store the data in.
     * onSuccess: @Function(@Array[@FPFile]). Function called when one or more files is picked successfully
     * onError: @Function(@FPError). Function called when there is an error picking files. Errors:
     *   101: The user closed the picker without choosing any file
     *   102: Unknown error in picking file
     *   151: The content store cannot be reached
     */
    var pickAndStore = function(picker_options, store_options, onSuccess, onError, onProgress) {
        checkApiKey();
        if (!picker_options || !store_options || 
                typeof picker_options === "function" || typeof picker_options === "function") {
            throw new fp.FilepickerException("Not all required parameters given, missing picker or store options");
        }

        onError = onError || fp.errors.handleError;

        var multiple = !!(picker_options['multiple']);
        //copying over options so as to not mutate them
        var options = !!picker_options ? fp.util.clone(picker_options) : {};

        options.storeLocation = store_options.location || 'S3';
        options.storePath = store_options.path;
        options.storeContainer = store_options.container;
        options.storeAccess = store_options.access || 'private';

        //If multiple, path must end in /
        if (multiple && options.storePath) {
            if (options.storePath.charAt(options.storePath.length - 1) != "/") {
                throw new fp.FilepickerException("pickAndStore with multiple files requires a path that ends in '/'");
            }
        }

        //to have a consistent array
        var success = onSuccess;
        if (!multiple) {
            success = function(resp){onSuccess([resp]);};
        }

        fp.picker.createPicker(options, success, onError, multiple, false, onProgress);
    };

    /**
     * Pops open the filepicker.io picker dialog to select a single folder.
     * Arguments:
     * options: @Object. Optional. Key-value pairs to tweak how the dialog looks and behaves. Valid options:
     *   service: @ServiceEnum: the service to pick from
     *   services: @Array[@ServiceEnum]: the services to pick from
     *   openTo: @ServiceEnum: the service to start on
     *   container: @String: either "window", "modal", or the id of the iframe to open in
     * onSuccess: @Function(@FPFile). Function called when a folder is picked successfully
     * onError: @Function(@FPError). Function called when there is an error picking a folder. Errors:
     *   101: The user closed the picker without choosing a folder
     *   102: Unknown error in picking folder
     */
    var pickFolder = function(options, onSuccess, onError) {
        checkApiKey();

        if (typeof options === "function") {
            //Shift left
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }

        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;

        fp.picker.createPicker(options, onSuccess, onError, false, true);
    };

    /**
     * Reads the contents of the inputted url, file input type, DOM file, or fpfile
     * Arguments:
     * input: @FPFile|@URL|@File|@Input<type=file>: The object to read from.
     * options: @Object. Optional. Key-value pairs to determine how to read the object. Valid options:
     *   base64encode: @Boolean. Default False. Whether the data should be converted to base64
     *   asText: @Boolean. Default False. Whether the data should be converted to text or left as binary
     *   cache: @Boolean. Default False. Whether the data should be pulled from the browser's cache if possible
     * onSuccess: @Function(@String). Function called when the data is read successfully
     * onError: @Function(@FPError). Function called when there is an error reading the file. Errors:
     *   111: Your browser doesn't support reading from DOM File objects
     *   112: Your browser doesn't support reading from different domains
     *   113: The website of the URL you provided does not allow other domains to read data
     *   114: The website of the URL you provided had an error
     *   115: File not found
     *   118: General read error
     * onProgress: @Function(Number). Function called on progress events
     */
    var read = function(input, options, onSuccess, onError, onProgress){
        checkApiKey();
        if (!input) {
            throw new fp.FilepickerException("No input given - nothing to read!");
        }

        if (typeof options === "function") {
            //Shift left
            onProgress = onError;
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }
    
        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;
        onProgress = onProgress || function(){};
        if (typeof input == "string") {
            if (fp.util.isFPUrl(input)) {
                fp.files.readFromFPUrl(input, options, onSuccess, onError, onProgress);
             } else {
                fp.files.readFromUrl(input, options, onSuccess, onError, onProgress);
             }
        } else if (fp.util.isFileInputElement(input)) {
            if (!input.files) {
                storeThenRead(input, options, onSuccess, onError, onProgress);
            } else if (input.files.length === 0) {
                onError(new fp.errors.FPError(115));
            } else {
                fp.files.readFromFile(input.files[0], options, onSuccess, onError, onProgress);
            }
        } else if (fp.util.isFile(input)) {
            fp.files.readFromFile(input, options, onSuccess, onError, onProgress);
        } else if (input.url) {
            //FPFile
            fp.files.readFromFPUrl(input.url, options, onSuccess, onError, onProgress);
        } else {
            throw new fp.FilepickerException("Cannot read given input: "+input+". Not a url, file input, DOM File, or FPFile object.");
        }
    };

    //Never surrender!
    var storeThenRead = function(input, readOptions, onSuccess, onError, onProgress) {
        onProgress(10);
        fp.store(input, function(fpfile){
            onProgress(50);
            fp.read(fpfile, readOptions, onSuccess, onError, function(progress){onProgress(50+progress/2);});
        }, onError);
    };

    /**
     * Writes the contents of the inputted data, file input type, DOM file, or fpfile to the given fpfile
     * Arguments:
     * fpfile: @FPFile|@FPUrl: The object to write to.
     * input: @Data|@FPFile|@File|@Input<type=file>: The object to read from.
     * options: @Object. Optional. Key-value pairs to determine how to read the object. Valid options:
     *   base64decode: @Boolean. Default False. Whether the data to write should be converted from base64
     * onSuccess: @Function(@FPFile). Function called when the data is read successfully
     * onError: @Function(@FPError). Function called when there is an error reading the file. Errors:
     *   111: Your browser doesn't support reading from DOM File objects
     *   115: Input file not found
     *   118: General read error
     *   121: The fpfile provided could not be found
     * onProgress: @Function(Number). Function called on progress events
     */
    var write = function(fpfile, input, options, onSuccess, onError, onProgress){
        checkApiKey();
        if (!fpfile) {
            throw new fp.FilepickerException("No fpfile given - nothing to write to!");
        }
        if (input === undefined || input === null) {
            throw new fp.FilepickerException("No input given - nothing to write!");
        }

        if (typeof options === "function") {
            //Shift left
            onProgress = onError;
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }
    
        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;
        onProgress = onProgress || function(){};

        var fp_url;
        if (fp.util.isFPUrl(fpfile)) {
            fp_url = fpfile;
        } else if (fpfile.url) {
            fp_url = fpfile.url;
        } else {
            throw new fp.FilepickerException("Invalid file to write to: "+fpfile+". Not a filepicker url or FPFile object.");
        }

        if (typeof input == "string") {
            fp.files.writeDataToFPUrl(fp_url, input, options, onSuccess, onError, onProgress);
        } else {
            if (fp.util.isFileInputElement(input)) {
                if (!input.files) {
                    fp.files.writeFileInputToFPUrl(fp_url, input, options, onSuccess, onError, onProgress);
                } else if (input.files.length === 0) {
                    onError(new fp.errors.FPError(115));
                } else {
                    fp.files.writeFileToFPUrl(fp_url, input.files[0], options, onSuccess, onError, onProgress);
                }
            } else if (fp.util.isFile(input)) {
                fp.files.writeFileToFPUrl(fp_url, input, options, onSuccess, onError, onProgress);
            } else if (input.url) {
                fp.files.writeUrlToFPUrl(fp_url, input.url, options, onSuccess, onError, onProgress);
            } else {
                throw new fp.FilepickerException("Cannot read from given input: "+input+". Not a string, file input, DOM File, or FPFile object.");
            }
        }
    };

    /**
     * Writes the contents of the inputted url to the given fpfile
     * Arguments:
     * fpfile: @FPFile|@FPUrl: The object to write to.
     * input: @URL: The url to read from.
     * options: @Object. Optional. Key-value pairs to determine how to read the object. Valid options:
     *   base64decode: @Boolean. Default False. Whether the data to write should be converted from base64
     * onSuccess: @Function(@String). Function called when the data is read successfully
     * onError: @Function(@FPError). Function called when there is an error reading the file. Errors:
     *   121: The fpfile provided could not be found
     *   122: The remote server had an error
     * onProgress: @Function(Number). Function called on progress events
     */
    var writeUrl = function(fpfile, input, options, onSuccess, onError, onProgress){
        checkApiKey();
        if (!fpfile) {
            throw new fp.FilepickerException("No fpfile given - nothing to write to!");
        }
        if (input === undefined || input === null) {
            throw new fp.FilepickerException("No input given - nothing to write!");
        }

        if (typeof options === "function") {
            //Shift left
            onProgress = onError;
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }
    
        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;
        onProgress = onProgress || function(){};

        var fp_url;
        if (fp.util.isFPUrl(fpfile)) {
            fp_url = fpfile;
        } else if (fpfile.url) {
            fp_url = fpfile.url;
        } else {
            throw new fp.FilepickerException("Invalid file to write to: "+fpfile+". Not a filepicker url or FPFile object.");
        }

        fp.files.writeUrlToFPUrl(fp_url, input, options, onSuccess, onError, onProgress);
    };

    /**
     * Pops open the filepicker.io picker dialog to export a single file.
     * Arguments:
     * input: @FPFile|@URL: The url of the object to read from.
     * options: @Object. Optional. Key-value pairs to tweak how the dialog looks and behaves. Valid options:
     *   service: @ServiceEnum: the service to allow the user to export to
     *   services: @Array[@ServiceEnum]: the services to allow the user to export to
     *   openTo: @ServiceEnum: the service to start on
     *   container: @String: either "window", "modal", or the id of the iframe to open in
     *   mimetype: @String: The mimetype of the file to export
     *   extension: @String: The extension of the file to export
     *   suggestedFilename: @String: The suggested filename to use
     *   debug: @Boolean: If true, returns immediately with dummy data
     * onSuccess: @Function(@FPFile). Function called when a file is exported successfully
     * onError: @Function(@FPError). Function called when there is an error exporting a file. Errors:
     *   131: The user closed the exporter without saving a file
     *   132: Error in exporting
     */
    var exportFn = function(input, options, onSuccess, onError) {
        checkApiKey();

        if (typeof options === "function") {
            //Shift left
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }

        options = !!options ? fp.util.clone(options) : {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;

        var fp_url;
        if (typeof input == "string" && fp.util.isUrl(input)) {
            fp_url = input;
        } else if (input.url) {
            fp_url = input.url;
            //make use of what we know
            if (!options.mimetype && !options.extension) {
                options.mimetype = input.mimetype;
            }
            if (!options.suggestedFilename) {
                options.suggestedFilename = input.filename;
            }
        } else {
            throw new fp.FilepickerException("Invalid file to export: "+input+". Not a valid url or FPFile object. You may want to use filepicker.store() to get an FPFile to export");
        }

        fp.exporter.createExporter(fp_url, options, onSuccess, onError);
    };

    /**
     * Stores the inputted file or data
     * Arguments:
     * input: @FPFile|@Data|@File|@Input<type=file>: The object to store.
     * options: @Object. Optional. Key-value pairs to tweak how the file is stored. Valid options:
     *   base64decode: @Boolean: whether the data should be base64decoded before storing
     *   location: @LocationEnum: the location to store the data in.
     *   path: @String: the path to save the file at in the data store
     *   container: @String: the container to save the file at in the data store
     *   filename: @String: the name of the file to save
     * onSuccess: @Function(@FPFile). Function called when a file is stored successfully
     * onError: @Function(@FPError). Function called when there is an error storing a file. Errors:
     *   151: The content store cannot be reached
     * onProgress: @Function(Number). Function called on progress events
     */
    var store = function(input, options, onSuccess, onError, onProgress) {
        checkApiKey();

        if (typeof options === "function") {
            //Shift left
            onProgress = onError;
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }

        options = !!options ? fp.util.clone(options) : {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;
        onProgress = onProgress || function(){};

        if (typeof input == "string") {
            fp.files.storeData(input, options, onSuccess, onError, onProgress);
        } else {
            if (fp.util.isFileInputElement(input)) {
                if (!input.files) {
                    fp.files.storeFileInput(input, options, onSuccess, onError, onProgress);
                } else if (input.files.length === 0) {
                    onError(new fp.errors.FPError(115));
                } else {
                    fp.files.storeFile(input.files[0], options, onSuccess, onError, onProgress);
                }
            } else if (fp.util.isFile(input)) {
                fp.files.storeFile(input, options, onSuccess, onError, onProgress);
            } else if (input.url) {
                //Guess filename if needed
                if (!options.filename) {
                    options.filename = input.filename;
                }
                fp.files.storeUrl(input.url, options, onSuccess, onError, onProgress);
            } else {
                throw new fp.FilepickerException("Cannot store given input: "+input+". Not a string, file input, DOM File, or FPFile object.");
            }
        }
    };

    /**
     * Stores the inputed url
     * Arguments:
     * input: @URL: The url to store.
     * options: @Object. Optional. Key-value pairs to tweak how the file is stored. Valid options:
     *   base64decode: @Boolean: whether the data should be base64decoded before storing
     *   location: @LocationEnum: the location to store the data in.
     *   path: @String: the path to save the file at in the data store
     *   container: @String: the container to save the file at in the data store
     *   filename: @String: the name of the file to save
     * onSuccess: @Function(@FPFile). Function called when a file is stored successfully
     * onError: @Function(@FPError). Function called when there is an error storing a file. Errors:
     *   151: The content store cannot be reached
     * onProgress: @Function(Number). Function called on progress events
     */
    var storeUrl = function(input, options, onSuccess, onError, onProgress) {
        checkApiKey();

        if (typeof options === "function") {
            //Shift left
            onProgress = onError;
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }
    
        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;
        onProgress = onProgress || function(){};

        fp.files.storeUrl(input, options, onSuccess, onError, onProgress);
    };


    /**
     * Gets metadata about the given fpfile
     * Arguments:
     * input: @FPFile: The fpfile to get metadata about.
     * options: @Object. Optional. Key-value pairs about what values to return. By default gives what info is easily available
     *    size: @Number: size of the file
     *    mimetype: @String: mimetype of the file
     *    filename: @String: given name of the file
     *    width: @Number: for images, the width of the image
     *    height: @Number: for images, the height of the image
     *    uploaded: @Date: when the file was uploaded to filepicker, in UTC
     *    writeable: @Boolean: whether the file is writeable
     * onSuccess: @Function(@Dict). Function called when the data is returned
     * onError: @Function(@FPError). Function called when there is an error fetching metadata for the a file. Errors:
     *   161: The file cannot be found
     *   162: Error fetching metadata
     */
    var stat = function(fpfile, options, onSuccess, onError) {
        checkApiKey();

        if (typeof options === "function") {
            //Shift left
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }
    
        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;


        var fp_url;
        if (fp.util.isFPUrl(fpfile)) {
            fp_url = fpfile;
        } else if (fpfile.url) {
            fp_url = fpfile.url;
        } else {
            throw new fp.FilepickerException("Invalid file to get metadata for: "+fpfile+". Not a filepicker url or FPFile object.");
        }
        fp.files.stat(fp_url, options, onSuccess, onError);
    };

    /**
     * Removes the given file
     * Arguments:
     * input: @FPFile: The fpfile to remove
     * options: @Object. Optional. Key-value pairs about how to remove the file. No values yet.
     * onSuccess: @Function(). Function called when the remove is successful
     * onError: @Function(@FPError). Function called when there is an error removing the file. Errors:
     *   171: The file cannot be found, and may have already been deleted
     *   172: The underlying content store cannot be reached
     */
    var remove = function(fpfile, options, onSuccess, onError) {
        checkApiKey();

        if (typeof options === "function") {
            //Shift left
            onError = onSuccess;
            onSuccess = options;
            options = {};
        }
    
        options = options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;


        var fp_url;
        if (fp.util.isFPUrl(fpfile)) {
            fp_url = fpfile;
        } else if (fpfile.url) {
            fp_url = fpfile.url;
        } else {
            throw new fp.FilepickerException("Invalid file to remove: "+fpfile+". Not a filepicker url or FPFile object.");
        }
        fp.files.remove(fp_url, options, onSuccess, onError);
    };

    /**
     * Creates a converted version of the inputted fpfile. Only works with images currently.
     * Arguments:
     * input: @FPFile: The fpfile to convert
     * conversion_options: @Object. Key-value pairs about how to convert the file.
     *    width: @Number: width to resize to.
     *    height: @Number: height to resize to.
     *    fit: @String: how to fit the resize. Values: 'crop', 'clip', 'scale', 'max'. Default: 'clip'
     *    align: @String: how to align the fit. Values: 'top', 'bottom', 'left', 'right', 'faces'. Default: center
     *    crop: [@Number,@Number,@Number,@Number] ||@String: crop the image to the specified rectangle
     *    format: @String: convert to the specified format. Values: 'jpg', 'png'
     *    quality: @Number: quality of the jpeg conversion, between 1-100
     *    watermark: @URL: url to use as a watermark
     *    watermark_size: @Number: scale the watermark to the given size as a % of the base image
     *    watermark_position: @String: align the watermark to the given position. Values are 'top','middle','bottom','left','center','right', or a combination thereof
     * store_options: @Object. Optional. Key-value pairs to tweak how the file is stored. Valid options:
     *   location: @LocationEnum: the location to store the data in.
     * onSuccess: @Function(@FPFile). Function called when the conversion is successful. Passes in the new FPFile
     * onError: @Function(@FPError). Function called when there is an error removing the file. Errors:
     *   141: The file cannot be found.
     *   142: The file cannot be converted with the specified parameters.
     *   143: Unknown error when converting the file.
     * onProgress: @Function(Number). Function called on progress events
     */
    var convert = function(fpfile, convert_options, store_options, onSuccess, onError, onProgress) {
        checkApiKey();
        if (!fpfile) {
            throw new fp.FilepickerException("No fpfile given - nothing to convert!");
        }

        if (typeof store_options === "function") {
            //Shift left
            onProgress = onError;
            onError = onSuccess;
            onSuccess = store_options;
            store_options = {};
        }
    
        options = !!convert_options ? fp.util.clone(convert_options) : {};
        store_options = store_options || {};
        onSuccess = onSuccess || function(){};
        onError = onError || fp.errors.handleError;
        onProgress = onProgress || function(){};

        if (store_options.location) {
            options.storeLocation = store_options.location;
        }
        if (store_options.path) {
            options.storePath = store_options.path;
        }
        if (store_options.container) {
            options.storeContainer = store_options.container;
        }
        options.storeAccess = store_options.access || 'private';

        var fp_url;
        if (fp.util.isFPUrl(fpfile)) {
            fp_url = fpfile;
        } else if (fpfile.url) {
            fp_url = fpfile.url;

            //Only images for now
            if (!fp.mimetypes.matchesMimetype(fpfile.mimetype, 'image/*')) {
                onError(new fp.errors.FPError(142));
                return;
            }
        } else {
            throw new fp.FilepickerException("Invalid file to convert: "+fpfile+". Not a filepicker url or FPFile object.");
        }
        fp.conversions.convert(fp_url, options, onSuccess, onError, onProgress);
    };

    //Have to alias because of module loading ordering
    var constructWidget = function(base) {
        return fp.widgets.constructWidget(base);
    };
    var makeDropPane = function(div, options) {
        return fp.dragdrop.makeDropPane(div, options);
    };

    return {
        setKey: setKey,
        pick: pick,
        pickFolder: pickFolder,
        pickMultiple: pickMultiple,
        pickAndStore: pickAndStore,
        read: read,
        write: write,
        writeUrl: writeUrl,
        'export': exportFn,
        exportFile: exportFn,
        store: store,
        storeUrl: storeUrl,
        stat: stat,
        metadata: stat,
        remove: remove,
        convert: convert,
        constructWidget: constructWidget,
        makeDropPane: makeDropPane,
        FilepickerException: FilepickerException
    };
}, true);
filepicker.extend('mimetypes', function(){
    var fp = this;

    /*We have a mimetype map to make up for the fact that browsers
     * don't yet recognize all the mimetypes we need to support*/
    var mimetype_extension_map = {
        '.stl':'application/sla',
        '.hbs':'text/html',
        '.pdf':'application/pdf',
        '.jpg':'image/jpeg',
        '.jpeg':'image/jpeg',
        '.jpe':'image/jpeg',
        '.imp':'application/x-impressionist'
    };

    var mimetype_bad_array = [ 'application/octet-stream',
                                'application/download',
                                'application/force-download',
                                'octet/stream',
                                'application/unknown',
                                'application/x-download',
                                'application/x-msdownload',
                                'application/x-secure-download'];

    var getMimetype = function(file) {
        if (file.type) {
            var type = file.type;
            type = type.toLowerCase();
            var bad_type = false;
            for (var n = 0; n < mimetype_bad_array.length; n++){
                bad_type = bad_type || type == mimetype_bad_array[n];
            }
            if (!bad_type){
                return file.type;
            }
        }
        var filename = file.name || file.fileName;
        var extension = filename.match(/\.\w*$/);
        if (extension) {
            return mimetype_extension_map[extension[0].toLowerCase()] || '';
        } else {
            if (file.type){
                //Might be a bad type, but better then nothing
                return file.type;
            } else {
                return '';
            }
        }
    };

    var matchesMimetype = function(test, against) {
        if (!test) {return against == "*/*";}

        test = fp.util.trim(test).toLowerCase();
        against = fp.util.trim(against).toLowerCase();

        // Firefox has some oddities as it allows the user to overwrite mimetypes.
        // These are some of the silly mimetypes that have no meaning at all
        for (var n = 0; n < mimetype_bad_array.length; n++){
            if (test == mimetype_bad_array[n]){
                return true;
            }
        }

        test_parts = test.split("/");
        against_parts = against.split("/");
        //comparing types
        if (against_parts[0] == "*") {return true;}
        if (against_parts[0] != test_parts[0]) {return false;}
        //comparing subtypes
        if (against_parts[1] == "*") {return true;}
        return against_parts[1] == test_parts[1];
    };

    return {
        getMimetype: getMimetype,
        matchesMimetype: matchesMimetype
    };
});
//modal.js
filepicker.extend("modal", function(){
    var fp = this;

    var SHADE_NAME = "filepicker_shade";
    var WINDOW_CONTAINER_NAME = "filepicker_dialog_container";

    /*
     * Make the code for the modal
     */
    var generateModal = function(modalUrl, onClose){
        var shade = createModalShade(onClose);
        var container = createModalContainer();
        var close = createModalClose(onClose);

        var modal = document.createElement("iframe");
        modal.name = fp.window.WINDOW_NAME;
        modal.id = fp.window.WINDOW_NAME;
        //modal.scrolling = 'no';
        var size = fp.window.getSize();
        var height = Math.min(size[1]-40, 500);
        modal.style.width = '100%';
        modal.style.height = height-32 + 'px';
        modal.style.border = "none";
        modal.style.position = "relative";
        //IE...
        modal.setAttribute('border',0);
        modal.setAttribute('frameborder',0);
        modal.setAttribute('frameBorder',0);
        modal.setAttribute('marginwidth',0);
        modal.setAttribute('marginheight',0);

        modal.src = modalUrl;

        document.body.appendChild(shade);
        container.appendChild(close);
        container.appendChild(modal);
        document.body.appendChild(container);

        return modal;
    };

    var createModalShade = function(onClose) {
        var shade = document.createElement("div");
        shade.id = SHADE_NAME;
        shade.style.position = 'fixed';
        shade.style.top = 0;
        shade.style.bottom = 0;
        shade.style.right = 0;
        shade.style.left = 0;
        shade.style.backgroundColor = '#000000';
        shade.style.opacity = '0.5';
        shade.style.filter = 'alpha(opacity=50)';
        shade.style.zIndex = 10000;
        shade.onclick = getCloseModal(onClose);
        return shade;
    };

    var createModalContainer = function() {
        var modalcontainer = document.createElement("div");
        modalcontainer.id = WINDOW_CONTAINER_NAME;
        modalcontainer.style.position = 'fixed';
        modalcontainer.style.padding = "10px";
        modalcontainer.style.background = '#ffffff url("http://www.local-fp.com/static/img/spinner.gif") no-repeat 50% 50%';
        modalcontainer.style.top = '10px';
        modalcontainer.style.bottom = 'auto';
        modalcontainer.style.right = 'auto';
        var size = fp.window.getSize();
        var height = Math.min(size[1]-40, 500);
        var width = Math.max(Math.min(size[0]-40, 800), 620);
        var leftspacing = (size[0]-width-40)/2;

        modalcontainer.style.left = leftspacing + "px";

        modalcontainer.style.height = height + 'px';
        modalcontainer.style.width = width + 'px';
        modalcontainer.style.overflow = 'hidden';
        modalcontainer.style.webkitOverflowScrolling = 'touch';
        modalcontainer.style.border = '1px solid #999';
        modalcontainer.style.webkitBorderRadius = '3px';
        modalcontainer.style.borderRadius = '3px';
        modalcontainer.style.margin = '0';
        modalcontainer.style.webkitBoxShadow = '0 3px 7px rgba(0, 0, 0, 0.3)';
        modalcontainer.style.boxShadow = '0 3px 7px rgba(0, 0, 0, 0.3)';
        modalcontainer.style.zIndex = 10001;
        // This helps with the modal going into mobile version
        modalcontainer.style.boxSizing = "content-box";
        modalcontainer.style.webkitBoxSizing = "content-box";
        modalcontainer.style.mozBoxSizing = "content-box";
        return modalcontainer;
    };

    var createModalClose = function(onClose) {
        var close = document.createElement("a");
        close.appendChild(document.createTextNode('\u00D7'));
        close.onclick = getCloseModal(onClose);
        close.style.cssFloat = "right";
        close.style.styleFloat = "right";
        close.style.cursor = "default";
        close.style.padding = '0 5px 0 0px';
        close.style.fontSize = '1.5em';
        close.style.color = '#555555';
        close.style.textDecoration = 'none';
        return close;
    };

    var getCloseModal = function(onClose, force){
        force = !!force;
        return function(){
            if (fp.uploading && !force) {
                if (!window.confirm("You are currently uploading. If you choose 'OK', the window will close and your upload will not finish. Do you want to stop uploading and close the window?")) {
                    return;
                }
            }
            fp.uploading = false;
            var shade = document.getElementById(SHADE_NAME);
            if (shade) {
                document.body.removeChild(shade);
            }
            var container = document.getElementById(WINDOW_CONTAINER_NAME);
            if (container) {
                document.body.removeChild(container);
            }
            try{delete window.frames[fp.window.WINDOW_NAME];}catch(e){}
            if (onClose){onClose();}
        };
    };

    var closeModal = getCloseModal(function(){});

    return {
        generate: generateModal,
        close: closeModal
    };
});
//picker.js
filepicker.extend("picker", function(){
    var fp = this;

    var normalizeOptions = function(options) {
        var normalize = function(singular, plural, def){
            if (options[plural]) {
                if (!fp.util.isArray(options[plural])) {
                    options[plural] = [options[plural]];
                }
            } else if (options[singular]) {
                options[plural] = [options[singular]];
            } else if (def) {
                options[plural] = def;
            }
        };

        normalize('service', 'services');
        normalize('mimetype', 'mimetypes');
        normalize('extension', 'extensions');

        if (options['services']) {
            for (var i = 0; i < options['services'].length; i++) {
                var service = (''+options['services'][i]).replace(" ","");

                if (fp.services[service] !== undefined) {//we use 0, so can't use !
                    service = fp.services[service];
                }

                options['services'][i] = service;
            }
        }

        if (options['mimetypes'] && options['extensions']) {
            throw fp.FilepickerException("Error: Cannot pass in both mimetype and extension parameters to the pick function");
        }
        if (!options['mimetypes'] && !options['extensions']){
            options['mimetypes'] = ['*/*'];
        }

        if (options['openTo']) {
            options['openTo'] = fp.services[options['openTo']] || options['openTo'];
        }

        fp.util.setDefault(options, 'container', 'modal');
    };

    var getPickHandler = function(onSuccess, onError) {
        var handler = function(data) {
            if (data.type !== "filepickerUrl"){
                return;
            }
            fp.uploading = false;

            if (data.error) {
                fp.util.console.error(data.error);
                onError(fp.errors.FPError(102));
            } else {
                var fpfile = {};
                //TODO: change payload to not require parsing
                fpfile.url = data.payload.url;
                fpfile.filename = data.payload.data.filename;
                fpfile.mimetype = data.payload.data.type;
                fpfile.size = data.payload.data.size;
                if (data.payload.data.key) {
                    fpfile.key = data.payload.data.key;
                }
                if (data.payload.data.container) {
                    fpfile.container = data.payload.data.container;
                }
                if (data.payload.data.path) {
                    fpfile.path = data.payload.data.path;
                }
                
                //TODO: get writeable
                fpfile.isWriteable = true;
                onSuccess(fpfile);
            }

            //Try to close a modal if it exists.
            fp.modal.close();
        };
        return handler;
    };

    var getPickFolderHandler = function(onSuccess, onError) {
        var handler = function(data) {
            if (data.type !== "filepickerUrl"){
                return;
            }
            fp.uploading = false;

            if (data.error) {
                fp.util.console.error(data.error);
                onError(fp.errors.FPError(102));
            } else {
                data.payload.data.url = data.payload.url;
                onSuccess(data.payload.data);
            }

            //Try to close a modal if it exists.
            fp.modal.close();
        };
        return handler;
    };

    var getUploadingHandler = function(onUploading) {
        onUploading = onUploading || function(){};
        var handler = function(data) {
            if (data.type !== "uploading") {
                return;
            }
            fp.uploading = !!data.payload;
            onUploading(fp.uploading);
        };
        return handler;
    };

    var fpfileFromPayload = function(payload) {
        var fpfile = {};
        var url = payload.url;
        if (url.url) {
            url = url.url;
        }
        fpfile.url = url;
        var data = payload.url.data || payload.data;
        fpfile.filename = data.filename;
        fpfile.mimetype = data.type;
        fpfile.size = data.size;

        if (data.key) {
            fpfile.key = data.key;
        }
        if (data.container) {
            fpfile.container = data.container;
        }
        if (data.path) {
            fpfile.path = data.path;
        }

        //TODO: get writeable
        fpfile.isWriteable = true;

        return fpfile;
    };

    var getPickMultipleHandler = function(onSuccess, onError, onProgress) {
        var handler = function(data) {
            if (data.type == "filepickerProgress"){
                if (onProgress) {
                    fpfile = fpfileFromPayload(data.payload);
                    onProgress(fpfile);
                }
                return;
            } else if (data.type !== "filepickerUrl") {
                return;
            }
            fp.uploading = false;

            if (data.error) {
                fp.util.console.error(data.error);
                onError(fp.errors.FPError(102));
            } else {
                var fpfiles = [];


                //TODO: change payload to not require parsing
                if (!fp.util.isArray(data.payload)) {
                    data.payload = [data.payload];
                }
                for (var i = 0; i < data.payload.length; i++) {
                    fpfile = fpfileFromPayload(data.payload[i]);
                    fpfiles.push(fpfile);
                }
                onSuccess(fpfiles);
            }

            //Try to close a modal if it exists.
            fp.modal.close();
        };
        return handler;
    };

    var createPicker = function(options, onSuccess, onError, multiple, folder, onProgress) {
        normalizeOptions(options);

        if (options['debug']) {
            //return immediately, but still async
            setTimeout(function(){
                onSuccess({
                    url: "http://www.local-fp.com/api/file/-nBq2onTSemLBxlcBWn1",
                    filename: 'test.png',
                    mimetype: 'image/png',
                    size:58979
                });
            }, 1);
            return;
        }

        if (fp.cookies.THIRD_PARTY_COOKIES === undefined) {
            //if you want a modal, then we need to wait until we know if 3rd party cookies allowed.
            fp.cookies.checkThirdParty(function(){createPicker(options, onSuccess, onError, !!multiple, folder, onProgress);});
            return;
        }

        var id = fp.util.getId();

        //Wrapper around on success to make sure we don't also fire on close
        var finished = false;
        var onSuccessMark = function(fpfile){
            finished = true;
            onSuccess(fpfile);
        };
        var onErrorMark = function(fperror){
            finished = true;
            onError(fperror);
        };

        var onClose = function(){
            if (!finished) {
                finished = true;
                onError(fp.errors.FPError(101));
            }
        };

        if (options['container'] == 'modal' && (options['mobile'] || fp.window.shouldForce())) {
            options['container'] = 'window';
        }

        var url;
        var handler;
        if (multiple) {
            url = fp.urls.constructPickUrl(options, id, true);
            handler = getPickMultipleHandler(onSuccessMark, onErrorMark, onProgress);
        } else if (folder) {
            url = fp.urls.constructPickFolderUrl(options, id);
            handler = getPickFolderHandler(onSuccessMark, onErrorMark);
        } else {
            url = fp.urls.constructPickUrl(options, id, false);
            handler = getPickHandler(onSuccessMark, onErrorMark);
        }

        fp.window.open(options['container'], url, onClose);
        fp.handlers.attach(id, handler);

        var key = id+"-upload";
        fp.handlers.attach(key, getUploadingHandler(function(){
            fp.handlers.detach(key);
        }));
    };

    return {
        createPicker: createPicker
    };
});
filepicker.extend('services', function(){
    /**
     * @ServiceEnum: the services we support
     * Don't use 0 as it might be confused with false
     */
    return {
        COMPUTER: 1,
        DROPBOX: 2,
        FACEBOOK: 3,
        GITHUB: 4,
        GMAIL: 5,
        IMAGE_SEARCH: 6,
        URL: 7,
        WEBCAM: 8,
        GOOGLE_DRIVE: 9,
        SEND_EMAIL: 10,
        INSTAGRAM: 11,
        FLICKR: 12,
        VIDEO: 13,
        EVERNOTE: 14,
        PICASA: 15,
        WEBDAV: 16,
        FTP: 17,
        ALFRESCO: 18,
        BOX: 19,
        SKYDRIVE: 20
    };
}, true);
//strutil.js
filepicker.extend('util', function(){
    var fp = this;

    var trim = function(string) {
        return string.replace(/^\s+|\s+$/g,"");
    };

    var URL_REGEX = /^(http|https)\:.*\/\//i;
    var isUrl = function(string) {
        return !!string.match(URL_REGEX);
    };

    var parseUrl = function(url) {
        //returns a dictonary of info about the url. Actually the best way to do it, although it seems odd
        if (!url || url.charAt(0) == '/') {
            url = window.location.protocol+"//"+window.location.host+url;
        }
        var a = document.createElement('a');
        a.href = url;
        //safari 4.0 and 5.1 do opposite things
        var host = a.hostname.indexOf(":") == -1 ? a.hostname : a.host;
        var ret = {
            source: url,
            protocol: a.protocol.replace(':',''),
            host: host,
            port: a.port,
            query: a.search,
            params: (function(){
                var ret = {},
                    seg = a.search.replace(/^\?/,'').split('&'),
                    len = seg.length, i = 0, s;
                for (;i<len;i++) {
                    if (!seg[i]) { continue; }
                    s = seg[i].split('=');
                    ret[s[0]] = s[1];
                }
                return ret;
            })(),
            file: (a.pathname.match(/\/([^\/?#]+)$/i) || [,''])[1],
            hash: a.hash.replace('#',''),
            path: a.pathname.replace(/^([^\/])/,'/$1'),
            relative: (a.href.match(/tps?:\/\/[^\/]+(.+)/) || [,''])[1],
            segments: a.pathname.replace(/^\//,'').split('/')
        };
        ret.origin = ret.protocol+"://"+ret.host+(ret.port ? ":"+ret.port : '');

        return ret;
    };

    var endsWith = function(str, suffix) {
            return str.indexOf(suffix, str.length - suffix.length) !== -1;
    };

    return {
        trim: trim,
        parseUrl: parseUrl,
        isUrl: isUrl,
        endsWith: endsWith
    };
});
//urls.js
filepicker.extend("urls", function(){
    var fp = this;

    var base = "http://www.local-fp.com";
    if (window.filepicker.hostname) {
        base = window.filepicker.hostname;
    }

    var dialog_base = base.replace("www", "dialog");
    var pick_url = dialog_base + "/dialog/open/";
    var export_url = dialog_base + "/dialog/save/";
    var pick_folder_url = dialog_base + "/dialog/folder/";
    var store_url = base + "/api/store/";

    var constructPickUrl = function(options, id, multiple) {
        return pick_url+
            "?key="+fp.apikey+
            "&id="+id+
            "&referrer="+window.location.hostname+
            "&iframe="+(options['container'] != 'window')+
            "&version="+fp.API_VERSION+
            (options['services'] ? "&s="+options['services'].join(",") : "")+
            (multiple ? "&multi="+!!multiple : "")+
            (options['mimetypes'] !== undefined ? "&m="+options['mimetypes'].join(",") : "")+
            (options['extensions'] !== undefined ? "&ext="+options['extensions'].join(",") : "")+
            (options['openTo'] !== undefined ? "&loc="+options['openTo'] : "")+
            (options['maxSize'] ? "&maxSize="+options['maxSize']: "")+
            (options['maxFiles'] ? "&maxFiles="+options['maxFiles']: "")+
            (options['signature'] ? "&signature="+options['signature'] : "")+
            (options['policy'] ? "&policy="+options['policy'] : "")+
            (options['mobile'] !== undefined ? "&mobile="+options['mobile'] : "")+
            (options['folders'] !== undefined ? "&folders="+options['folders'] : "")+
            (options['storeLocation'] ? "&storeLocation="+options['storeLocation'] : "")+
            (options['storePath'] ? "&storePath="+options['storePath'] : "")+
            (options['storeContainer'] ? "&storeContainer="+options['storeContainer'] : "")+
            (options['storeAccess'] ? "&storeAccess="+options['storeAccess'] : "");
    };

    var constructPickFolderUrl = function(options, id) {
        return pick_folder_url+
            "?key="+fp.apikey+
            "&id="+id+
            "&referrer="+window.location.hostname+
            "&iframe="+(options['container'] != 'window')+
            "&version="+fp.API_VERSION+
            (options['services'] ? "&s="+options['services'].join(",") : "")+
            (options['openTo'] !== undefined ? "&loc="+options['openTo'] : "")+
            (options['signature'] ? "&signature="+options['signature'] : "")+
            (options['policy'] ? "&policy="+options['policy'] : "")+
            (options['mobile'] !== undefined ? "&mobile="+options['mobile'] : "");
    };

    var constructExportUrl = function(url, options, id) {
        if (url.indexOf("&") >= 0 || url.indexOf("?") >= 0) {
            url = encodeURIComponent(url);
        }
        return export_url+
            "?url="+url+
            "&key="+fp.apikey+
            "&id="+id+
            "&referrer="+window.location.hostname+
            "&iframe="+(options['container'] != 'window')+
            "&version="+fp.API_VERSION+
            (options['services'] ? "&s="+options['services'].join(",") : "")+
            (options['openTo'] !== undefined ? "&loc="+options['openTo'] : "")+
            (options['mimetype'] !== undefined ? "&m="+options['mimetype'] : "")+
            (options['extension'] !== undefined ? "&ext="+options['extension'] : "")+
            (options['mobile'] !== undefined ? "&mobile="+options['mobile'] : "")+
            (options['suggestedFilename'] !== undefined ? "&defaultSaveasName="+options['suggestedFilename'] : "")+
            (options['signature'] ? "&signature="+options['signature'] : "")+
            (options['policy'] ? "&policy="+options['policy'] : "");
    };

    var constructStoreUrl = function(options) {
        return store_url + options['location'] +
            "?key="+fp.apikey+
            (options['base64decode'] ? "&base64decode=true" : "")+
            (options['mimetype'] ? "&mimetype="+options['mimetype'] : "")+
            (options['filename'] ? "&filename="+options['filename'] : "")+
            (options['path'] ? "&path="+options['path'] : "")+
            (options['container'] ? "&container="+options['container'] : "")+
            (options['access'] ? "&access="+options['access'] : "")+
            (options['signature'] ? "&signature="+options['signature'] : "")+
            (options['policy'] ? "&policy="+options['policy'] : "");
    };

    var constructWriteUrl = function(fp_url, options) {
        //to make sure that fp_url already has a ?
        return fp_url +
            "?nonce=fp"+
            (!!options['base64decode'] ? "&base64decode=true" : "")+
            (options['mimetype'] ? "&mimetype="+options['mimetype'] : "")+
            (options['signature'] ? "&signature="+options['signature'] : "")+
            (options['policy'] ? "&policy="+options['policy'] : "");
    };

    var constructHostCommFallback = function(){
        var parts = fp.util.parseUrl(window.location.href);
        return parts.origin+"/404";
    };

    return {
        BASE: base,
        DIALOG_BASE: dialog_base,
        COMM: dialog_base + "/dialog/comm_iframe/",
        FP_COMM_FALLBACK: dialog_base + "/dialog/comm_hash_iframe/",
        STORE: store_url,
        PICK: pick_url, 
        EXPORT: export_url,
        constructPickUrl: constructPickUrl,
        constructPickFolderUrl: constructPickFolderUrl,
        constructExportUrl: constructExportUrl,
        constructWriteUrl: constructWriteUrl,
        constructStoreUrl: constructStoreUrl,
        constructHostCommFallback: constructHostCommFallback
    };
});
//util.js
filepicker.extend("util", function(){
    var fp = this;
    var isArray = function(o) {
        return o && Object.prototype.toString.call(o) === '[object Array]';
    };

    var isFile = function(o) {
        return o && Object.prototype.toString.call(o) === '[object File]';
    };

    var isElement = function(o) {
      //Returns true if it is a DOM element    
      if (typeof HTMLElement === "object") {
         return o instanceof HTMLElement; //DOM2
      } else {
        return o && typeof o === "object" && o.nodeType === 1 && typeof o.nodeName==="string";
      }
    };


    var isFileInputElement = function(o) {
        return isElement(o) && o.tagName == "INPUT" && o.type == "file";
    };

    var typeOf = function(value){
        if (value === null) {
            return 'null';
        } else if (isArray(value)) {
            return 'array';
        } else if (isFile(value)) {
            return 'file';
        }
        return typeof value;
    };

    var getId = function(){
        var d = new Date();
        return d.getTime().toString();
    };
    
    var setDefault = function(obj, key, def) {
        if (obj[key] === undefined) {
            obj[key] = def;
        }
    };

    var addOnLoad = function(func) {
        //We check for jquery - if we have it, use document.ready, else window onload
        if (window.jQuery) {
            window.jQuery(function(){
                func();
            });
        } else {
            var evnt = "load";
            if (window.addEventListener)  // W3C DOM
                window.addEventListener(evnt,func,false);
            else if (window.attachEvent) { // IE DOM
                window.attachEvent("on"+evnt, func);
            } else {
                if (window.onload) {
                    var curr = window.onload;
                    window.onload = function(){
                        curr();
                        func();
                    };
                } else {
                    window.onload = func;
                }
            }
        }
    };

    //should probably be moved to strutils
    var isFPUrl = function(url) {
        return typeof url == "string" && url.match("www.local-fp.com/api/file/");
    };

    var consoleWrap = function(fn) {
        return function(){
            if (window.console && typeof window.console[fn] == "function") {
                try {
                    window.console[fn].apply(window.console, arguments);
                } catch (e) {
                    alert(Array.prototype.join.call(arguments, ","));
                }
            }
        };
    };

    var console = {};
    console.log = consoleWrap("log");
    console.error = consoleWrap("error");

    //Note - only does shallow clones
    var clone = function(o) {
        var ret = {};
        for (key in o) {
            ret[key] = o[key];
        }
        return ret;
    };

    var standardizeFPFile = function(json){
        var fpfile = {};
        fpfile.url = json.url;
        fpfile.filename = json.filename || json.name;
        fpfile.mimetype = json.mimetype || json.type;
        fpfile.size = json.size;
        fpfile.key = json.key || json.s3_key;
        fpfile.isWriteable = !!(json.isWriteable || json.writeable);

        return fpfile;
    };

    return {
        isArray: isArray,
        isFile: isFile,
        isElement: isElement,
        isFileInputElement: isFileInputElement,
        getId: getId,
        setDefault: setDefault,
        typeOf: typeOf,
        addOnLoad: addOnLoad,
        isFPUrl: isFPUrl,
        console: console,
        clone: clone,
        standardizeFPFile: standardizeFPFile
    };
});
//widgets.js
filepicker.extend("widgets", function(){
    var fp = this;

    var setAttrIfExists = function(key, options, attrname, dom) {
        var val = dom.getAttribute(attrname);
        if (val) {
            options[key] = val;
        }
    };

    var fireOnChangeEvent = function(input, fpfiles){
        var e;
        if (document.createEvent) {
            e = document.createEvent('Event');
            e.initEvent("change", true, false);
            //When we clear, we fire onchange with undefined
            e.fpfile = fpfiles ? fpfiles[0] : undefined;
            e.fpfiles = fpfiles;
            input.dispatchEvent(e);
        } else if (document.createEventObject) {
            e = document.createEventObject('Event');
            e.eventPhase = 2;
            e.currentTarget = e.srcElement = e.target = input;
            //When we clear, we fire onchange with undefined
            e.fpfile = fpfiles ? fpfiles[0] : undefined;
            e.fpfiles = fpfiles;
            input.fireEvent('onchange', e);
        } else if (input.onchange) {
            input.onchange(fpfiles);
        }
    };

    /**
     * Constructs the standard pick widget
     * Arguments:
     * domObject: @DOMElement. The element in the dom to build on. Should be an input type="filepicker"
     */
    var constructPickWidget = function(domElement) {
        var widget = document.createElement("button");
        //So it's not submit
        //widget.type = 'button' will break ie8
        widget.setAttribute('type', 'button');

        widget.innerHTML = domElement.getAttribute('data-fp-button-text') ||
                domElement.getAttribute('data-fp-text') || "Pick File";
        widget.className = domElement.getAttribute('data-fp-button-class') ||
                domElement.getAttribute('data-fp-class') || domElement.className;

        domElement.style.display = "none";

        var fpoptions = {};
        //The old ones. TODO: get rid of when no longer needed
        setAttrIfExists("container", fpoptions, "data-fp-option-container", domElement);
        setAttrIfExists("maxSize", fpoptions, "data-fp-option-maxsize", domElement);

        setAttrIfExists("mimetype", fpoptions, "data-fp-mimetype", domElement);
        setAttrIfExists("mimetypes", fpoptions, "data-fp-mimetypes", domElement);
        setAttrIfExists("extension", fpoptions, "data-fp-extension", domElement);
        setAttrIfExists("extensions", fpoptions, "data-fp-extensions", domElement);
        setAttrIfExists("container", fpoptions, "data-fp-container", domElement);
        setAttrIfExists("maxSize", fpoptions, "data-fp-maxSize", domElement);
        setAttrIfExists("maxFiles", fpoptions, "data-fp-maxFiles", domElement);
        setAttrIfExists("openTo", fpoptions, "data-fp-openTo", domElement);
        setAttrIfExists("debug", fpoptions, "data-fp-debug", domElement);
        setAttrIfExists("signature", fpoptions, "data-fp-signature", domElement);
        setAttrIfExists("policy", fpoptions, "data-fp-policy", domElement);
        setAttrIfExists("storeLocation", fpoptions, "data-fp-store-location", domElement);
        setAttrIfExists("storePath", fpoptions, "data-fp-store-path", domElement);
        setAttrIfExists("storeContainer", fpoptions, "data-fp-store-container", domElement);
        setAttrIfExists("storeAccess", fpoptions, "data-fp-store-access", domElement);

        var services = domElement.getAttribute("data-fp-services");
        //Old
        if (!services) { 
            services = domElement.getAttribute("data-fp-option-services");
        }

        if (services) {
            services = services.split(",");
            for (var j=0; j<services.length; j++) {
                services[j] = fp.services[services[j].replace(" ","")];
            }
            fpoptions['services'] = services;
        }
        var service = domElement.getAttribute("data-fp-service");
        if (service) {
            fpoptions['service'] = fp.services[service.replace(" ","")];
        }

        if (fpoptions['mimetypes']) {
            fpoptions['mimetypes'] = fpoptions['mimetypes'].split(",");
        }
        if (fpoptions['extensions']) {
            fpoptions['extensions'] = fpoptions['extensions'].split(",");
        }

        var apikey = domElement.getAttribute("data-fp-apikey");
        if (apikey) {
            fp.setKey(apikey);
        }

        fpoptions['folders'] = (domElement.getAttribute("data-fp-folders") || "false") == "true";

        var multiple = (domElement.getAttribute("data-fp-multiple") ||
                domElement.getAttribute("data-fp-option-multiple") ||
                "false") == "true";

        if (multiple) {
            widget.onclick = function() {
                widget.blur();
                fp.pickMultiple(fpoptions, function(fpfiles){
                    var urls = [];
                    for (var j=0; j<fpfiles.length; j++) {
                        urls.push(fpfiles[j].url);
                    }
                    domElement.value = urls.join();
                    fireOnChangeEvent(domElement, fpfiles);
                });
                return false;
            };
        } else {
            widget.onclick = function(){
                widget.blur();
                fp.pick(fpoptions, function(fpfile){
                    domElement.value = fpfile.url;
                    fireOnChangeEvent(domElement, [fpfile]);
                });
                return false;
            };
        }
        // insert the filepicker button after the target domElement
        // it does this by inserting before the nextSibling of the target domElement - if nextSibling is null, insertBefore() acts like appendChild() and inserts the element at the end of the parent
        // http://stackoverflow.com/questions/4793604/how-to-do-insert-after-in-javascript-without-using-a-library
        domElement.parentNode.insertBefore(widget, domElement.nextSibling);
    };

    /**
     * Constructs the pick widget along with a drag-drop pane along with a drag-drop pane along with a drag-drop pane along with a drag-drop pane
     * Arguments:
     * domObject: @DOMElement. The element in the dom to build on. Should be an input type="filepicker-dragdrop"
     */
    var constructDragWidget = function(domElement) {
        var pane = document.createElement("div");
        pane.className = domElement.getAttribute('data-fp-class') || domElement.className;
        pane.style.padding = "1px";
        //pane.style.display = "inline-block";

        // inserts the pane after the target domElement
        domElement.style.display = "none";
        domElement.parentNode.insertBefore(pane, domElement.nextSibling);

        var pickButton = document.createElement("button");
        //So it's not submit
        //pickButton.type = 'button' will break ie8
        pickButton.setAttribute('type', 'button');
        pickButton.innerHTML = domElement.getAttribute('data-fp-button-text') || "Pick File";
        pickButton.className = domElement.getAttribute('data-fp-button-class') || '';
        pane.appendChild(pickButton);

        var dragPane = document.createElement("div");
        setupDragContainer(dragPane);

        dragPane.innerHTML = domElement.getAttribute('data-fp-drag-text') || "Or drop files here";
        dragPane.className = domElement.getAttribute('data-fp-drag-class') || '';

        pane.appendChild(dragPane);

        var fpoptions = {};
        //The old ones. TODO: get rid of when no longer needed
        setAttrIfExists("container", fpoptions, "data-fp-option-container", domElement);
        setAttrIfExists("maxSize", fpoptions, "data-fp-option-maxsize", domElement);

        setAttrIfExists("mimetype", fpoptions, "data-fp-mimetype", domElement);
        setAttrIfExists("mimetypes", fpoptions, "data-fp-mimetypes", domElement);
        setAttrIfExists("extension", fpoptions, "data-fp-extension", domElement);
        setAttrIfExists("extensions", fpoptions, "data-fp-extensions", domElement);
        setAttrIfExists("container", fpoptions, "data-fp-container", domElement);
        setAttrIfExists("maxSize", fpoptions, "data-fp-maxSize", domElement);
        setAttrIfExists("openTo", fpoptions, "data-fp-openTo", domElement);
        setAttrIfExists("debug", fpoptions, "data-fp-debug", domElement);
        setAttrIfExists("signature", fpoptions, "data-fp-signature", domElement);
        setAttrIfExists("policy", fpoptions, "data-fp-policy", domElement);
        setAttrIfExists("storeLocation", fpoptions, "data-fp-store-location", domElement);
        setAttrIfExists("storePath", fpoptions, "data-fp-store-path", domElement);
        setAttrIfExists("storeContainer", fpoptions, "data-fp-store-container", domElement);
        setAttrIfExists("storeAccess", fpoptions, "data-fp-store-access", domElement);

        var services = domElement.getAttribute("data-fp-services");
        //Old
        if (!services) { 
            services = domElement.getAttribute("data-fp-option-services");
        }
        if (services) {
            services = services.split(",");
            for (var j=0; j<services.length; j++) {
                services[j] = fp.services[services[j].replace(" ","")];
            }
            fpoptions['services'] = services;
        }
        var service = domElement.getAttribute("data-fp-service");
        if (service) {
            fpoptions['service'] = fp.services[service.replace(" ","")];
        }

        if (fpoptions['mimetypes']) {
            fpoptions['mimetypes'] = fpoptions['mimetypes'].split(",");
        }
        if (fpoptions['extensions']) {
            fpoptions['extensions'] = fpoptions['extensions'].split(",");
        }

        var apikey = domElement.getAttribute("data-fp-apikey");
        if (apikey) {
            fp.setKey(apikey);
        }

        var multiple = (domElement.getAttribute("data-fp-multiple") ||
                domElement.getAttribute("data-fp-option-multiple") ||
                "false") == "true";

        if (fp.dragdrop.enabled()) {
            setupDropPane(dragPane, multiple, fpoptions, domElement);
        } else {
            dragPane.innerHTML = "&nbsp;";
        }

        if (multiple) {
            dragPane.onclick = pickButton.onclick = function(){
                pickButton.blur();
                fp.pickMultiple(fpoptions, function(fpfiles){
                    var urls = [];
                    var filenames = [];
                    for (var j=0; j<fpfiles.length; j++) {
                        urls.push(fpfiles[j].url);
                        filenames.push(fpfiles[j].filename);
                    }
                    domElement.value = urls.join();
                    onFilesUploaded(domElement, dragPane, filenames.join(', '));
                    fireOnChangeEvent(domElement, fpfiles);
                });
                return false;
            };
        } else {
            dragPane.onclick = pickButton.onclick = function(){
                pickButton.blur();
                fp.pick(fpoptions, function(fpfile){
                    domElement.value = fpfile.url;
                    onFilesUploaded(domElement, dragPane, fpfile.filename);
                    fireOnChangeEvent(domElement, [fpfile]);
                });
                return false;
            };
        }
    };

    var onFilesUploaded = function(input, odrag, text) {
        odrag.innerHTML = text;
        odrag.style.padding = "2px 4px";
        odrag.style.cursor = "default";
        odrag.style.width = '';

        var cancel = document.createElement("span");
        cancel.innerHTML = "X";
        cancel.style.borderRadius = "8px";
        cancel.style.fontSize = "14px";
        cancel.style.cssFloat = "right";
        cancel.style.padding = "0 3px";
        cancel.style.color = "#600";
        cancel.style.cursor = "pointer";

        var clickFn = function(e) {
            if (!e) {
                e = window.event;
            }
            e.cancelBubble = true;
            if (e.stopPropagation) {
                e.stopPropagation();
            }

            //reset
            setupDragContainer(odrag);
            if (!fp.dragdrop.enabled) {
                odrag.innerHTML = '&nbsp;';
            } else {
                odrag.innerHTML = input.getAttribute('data-fp-drag-text') || "Or drop files here";
            }

            input.value = '';
            fireOnChangeEvent(input);
            return false;
        };

        if (cancel.addEventListener) {
            cancel.addEventListener("click", clickFn, false);
        } else if (cancel.attachEvent) {
            cancel.attachEvent("onclick", clickFn);
        }

        odrag.appendChild(cancel);
    };

    var setupDragContainer = function(dragPane) {
        dragPane.style.border = "1px dashed #AAA";
        dragPane.style.display = "inline-block";
        dragPane.style.margin = "0 0 0 4px";
        dragPane.style.borderRadius = "3px";
        dragPane.style.backgroundColor = "#F3F3F3";
        dragPane.style.color = "#333";
        dragPane.style.fontSize = "14px";
        dragPane.style.lineHeight = "22px";
        dragPane.style.padding = "2px 4px";
        dragPane.style.verticalAlign = "middle";
        dragPane.style.cursor = "pointer";
        dragPane.style.overflow = "hidden";
    };

    var setupDropPane = function(odrag, multiple, fpoptions, input) {
        var text = odrag.innerHTML;
        var pbar;
        fp.dragdrop.makeDropPane(odrag, {
            multiple: multiple,
            maxSize: fpoptions['maxSize'],
            mimetypes: fpoptions['mimetypes'],
            mimetype: fpoptions['mimetype'],
            extensions: fpoptions['extensions'],
            extension: fpoptions['extension'],
            /*Storing config*/
            location: fpoptions['storeLocation'],
            path: fpoptions['storePath'],
            container: fpoptions['storeContainer'],
            access: fpoptions['storeAccess'],
            policy: fpoptions['policy'],
            signature: fpoptions['signature'],
            /*events*/
            dragEnter: function() {
                odrag.innerHTML = "Drop to upload";
                odrag.style.backgroundColor = "#E0E0E0";
                odrag.style.border = "1px solid #000";
            },
            dragLeave: function() {
                odrag.innerHTML = text;
                odrag.style.backgroundColor = "#F3F3F3";
                odrag.style.border = "1px dashed #AAA";
            },
            onError: function(type, msg) {
                if (type == "TooManyFiles") {
                    odrag.innerHTML = msg;
                } else if (type == "WrongType") {
                    odrag.innerHTML = msg;
                } else if (type == "NoFilesFound") {
                    odrag.innerHTML = msg;
                } else if (type == "UploadError") {
                    odrag.innerHTML = "Oops! Had trouble uploading.";
                }
            },
            onStart: function(files) {
                pbar = setupProgress(odrag);
            },
            onProgress: function(percentage) {
                if (pbar) {
                    pbar.style.width = percentage+"%";
                }
            },
            onSuccess: function(fpfiles) {
                var vals = [];
                var filenames = [];
                for (var i = 0; i < fpfiles.length; i++){
                    vals.push(fpfiles[i].url);
                    filenames.push(fpfiles[i].filename);
                }
                input.value = vals.join();
                onFilesUploaded(input, odrag, filenames.join(', '));
                fireOnChangeEvent(input, fpfiles);
            }
        });
    };

    var setupProgress = function(odrag) {
        var pbar = document.createElement("div");
        var height = odrag.offsetHeight - 2;
        pbar.style.height = height + "px";
        pbar.style.backgroundColor = "#0E90D2";
        pbar.style.width = "2%";
        pbar.style.borderRadius = "3px";

        odrag.style.width = odrag.offsetWidth + "px";
        odrag.style.padding = "0";
        odrag.style.border = "1px solid #AAA";
        odrag.style.backgroundColor = "#F3F3F3";
        odrag.style.boxShadow = "inset 0 1px 2px rgba(0, 0, 0, 0.1)";
        odrag.innerHTML = "";
        odrag.appendChild(pbar);
        return pbar;
    };

    /**
     * Constructs the standard export widget
     * Arguments:
     * domObject: @DOMElement. The element in the dom to build on. Should be an element with data-fp-url set
     */
    var constructExportWidget = function(domElement) {
        //Most likely they will want to set things like data-fp-url on the fly, so
        //we get the properties dynamically
        domElement.onclick = function(){
            var url = domElement.getAttribute("data-fp-url");
            if (!url) {
                return true;
            }

            var fpoptions = {};
            //The old ones. TODO: get rid of when no longer needed
            setAttrIfExists("container", fpoptions, "data-fp-option-container", domElement);
            setAttrIfExists("suggestedFilename", fpoptions, "data-fp-option-defaultSaveasName", domElement);

            setAttrIfExists("container", fpoptions, "data-fp-container", domElement);
            setAttrIfExists("suggestedFilename", fpoptions, "data-fp-suggestedFilename", domElement);
            setAttrIfExists("mimetype", fpoptions, "data-fp-mimetype", domElement);
            setAttrIfExists("extension", fpoptions, "data-fp-extension", domElement);

            var services = domElement.getAttribute("data-fp-services");
            if (!services) { 
                services = domElement.getAttribute("data-fp-option-services");
            }
            if (services) {
                services = services.split(",");
                for (var j=0; j<services.length; j++) {
                    services[j] = fp.services[services[j].replace(" ","")];
                }
                fpoptions['services'] = services;
            }
            var service = domElement.getAttribute("data-fp-service");
            if (service) {
                fpoptions['service'] = fp.services[service.replace(" ","")];
            }

            apikey = domElement.getAttribute("data-fp-apikey");
            if (apikey) {
                fp.setKey(apikey);
            }

            fp.exportFile(url, fpoptions);

            return false;
        };
    };


    /**
     * Builds all the widgets, searching through the current DOM
     */
    var buildWidgets = function(){
        if (document.querySelectorAll) {
            //Pick Widgets
            var i;
            var pick_base = document.querySelectorAll('input[type="filepicker"]');
            for (i = 0; i < pick_base.length; i++) {
                constructPickWidget(pick_base[i]);
            }
            var drag_widgets = document.querySelectorAll('input[type="filepicker-dragdrop"]');
            for (i = 0; i < drag_widgets.length; i++) {
                constructDragWidget(drag_widgets[i]);
            }

            var export_base = [];
            var tmp = document.querySelectorAll('button[data-fp-url]');
            for (i=0; i< tmp.length; i++) {
                export_base.push(tmp[i]);
            }
            tmp = document.querySelectorAll('a[data-fp-url]');
            for (i=0; i< tmp.length; i++) {
                export_base.push(tmp[i]);
            }
            tmp = document.querySelectorAll('input[type="button"][data-fp-url]');
            for (i=0; i< tmp.length; i++) {
                export_base.push(tmp[i]);
            }
            for (i=0; i < export_base.length; i++) {
                constructExportWidget(export_base[i]);
            }
        }
    };

    var constructWidget = function(base) {
        if (base.jquery) {
            base = base[0];
        }

        var base_type = base.getAttribute('type');
        if (base_type == 'filepicker'){
            constructPickWidget(base);
        } else if (base_type == 'filepicker-dragdrop'){
            constructDragWidget(base);
        } else {
            constructExportWidget(base);
        }
    };

    return {
        constructPickWidget: constructPickWidget,
        constructDragWidget: constructDragWidget,
        constructExportWidget: constructExportWidget,
        buildWidgets: buildWidgets,
        constructWidget: constructWidget
    };
});
//windows.js
filepicker.extend('window', function(){
    var fp = this;

    var DIALOG_TYPES = {
        OPEN:'/dialog/open/',
        SAVEAS:'/dialog/save/'
    };

    var WINDOW_NAME = "filepicker_dialog";
    var WINDOW_PROPERTIES = "left=100,top=100,height=600,width=800,menubar=no,toolbar=no,location=no,personalbar=no,status=no,resizable=yes,scrollbars=yes,dependent=yes,dialog=yes";
    var CLOSE_CHECK_INTERVAL = 1000;

    var getWindowSize = function(){
        if (document.body && document.body.offsetWidth) {
            winW = document.body.offsetWidth;
            winH = document.body.offsetHeight;
        }
        if (document.compatMode=='CSS1Compat' &&
                document.documentElement &&
                document.documentElement.offsetWidth ) {
            winW = document.documentElement.offsetWidth;
            winH = document.documentElement.offsetHeight;
        }
        if (window.innerWidth && window.innerHeight) {
            winW = window.innerWidth;
            winH = window.innerHeight;
        }
        return [winW, winH];
    };

    var shouldForce = function(){
        var smallScreen = getWindowSize()[0] < 768;
        var noCookies = fp.cookies.THIRD_PARTY_COOKIES === false;
        //if the window is too small, or no cookies, no modal.
        return fp.browser.isIOS() || fp.browser.isAndroid() || smallScreen || noCookies;
    };

    var openWindow = function(container, src, onClose) {
        onClose = onClose || function(){};
        if (!container){
            container = 'modal';
        }
        if (container == 'modal' && shouldForce()) {
            container = 'window';
        }

        if (container == 'window') {
            var name = WINDOW_NAME + fp.util.getId();
            var win = window.open(src, name, WINDOW_PROPERTIES);
            var closeCheck = window.setInterval(function(){
                if (!win || win.closed) {
                    window.clearInterval(closeCheck);
                    onClose();
                }
            }, CLOSE_CHECK_INTERVAL);
        } else if (container == 'modal') {
            fp.modal.generate(src, onClose);
        } else {
            var container_iframe = document.getElementById(container);
            if (!container_iframe) {
                throw new fp.FilepickerException("Container '"+container+"' not found. This should either be set to 'window','modal', or the ID of an iframe that is currently in the document.");
            }
            container_iframe.src = src;
        }
    };

    return {
        open: openWindow,
        WINDOW_NAME: WINDOW_NAME,
        getSize: getWindowSize,
        shouldForce: shouldForce
    };
});
(function(){
    //setup functions
    filepicker.internal(function(){
        var fp = this;
        fp.util.addOnLoad(fp.cookies.checkThirdParty);
        fp.util.addOnLoad(fp.widgets.buildWidgets);
    });

    //Now we wipe our superpowers
    delete filepicker.internal;
    delete filepicker.extend;

    //process the queue
    var queue = filepicker._queue || [];
    var args;
    var len = queue.length;
    if (len) {
        for (var i = 0; i < len; i++) {
            args = queue[i];
            filepicker[args[0]].apply(filepicker, args[1]);
        }
    }

    //remove the queue
    if (filepicker._queue) {
        delete filepicker._queue;
    }
})();
