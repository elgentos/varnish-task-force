# A number of these changes come form the following PR's; , combines changes in https://github.com/magento/magento2/pull/29360, https://github.com/magento/magento2/pull/28944 and https://github.com/magento/magento2/pull/28894, https://github.com/magento/magento2/pull/35228, https://github.com/magento/magento2/pull/36524, https://github.com/magento/magento2/pull/34323
# VCL version 5.0 is not supported so it should be 4.0 even though actually used Varnish version is 6

# See the non-Xkey version here: https://gist.github.com/peterjaap/006169c5d95eeffde3a1cc062de1b514

vcl 4.1;

import std;
import xkey;

# The minimal Varnish version is 6.0
# For SSL offloading, pass the following header in your proxy server or load balancer: '/* {{ ssl_offloaded_header }} */: https'

backend default {
    .host = "/* {{ host }} */";
    .port = "/* {{ port }} */";
    .first_byte_timeout = 600s;
#    .probe = {
#        .url = "/health_check.php";
#        .timeout = 2s;
#        .interval = 5s;
#        .window = 10;
#        .threshold = 5;
#   }
}

acl purge {
/* {{ ips }} */
}

sub vcl_recv {
    # Add support for Prismic preview functionality
    if (req.http.Cookie ~ "io.prismic.preview") {
        return (pass);
    }
        
    # Bypass generated sitemap files
    if (req.url ~ "^/sitemaps/") {
        return (pass);
    }

    # Remove empty query string parameters
    # e.g.: www.example.com/index.html?    
    if (req.url ~ "\?$") {
        set req.url = regsub(req.url, "\?$", "");
    }

    # Remove port number from host header
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    
    # Sorts query string parameters alphabetically for cache normalization purposes    
    set req.url = std.querysort(req.url);
    
    # Remove the proxy header to mitigate the httpoxy vulnerability
    # See https://httpoxy.org/    
    unset req.http.proxy;
    
    # Add X-Forwarded-Proto header when using https
    if (!req.http.X-Forwarded-Proto && (std.port(server.ip) == 443 || std.port(server.ip) == 8443)) {
        set req.http.X-Forwarded-Proto = "https";
    }
    
    # Reduce grace to the configured setting if the backend is healthy
    # In case of an unhealthy backend, the original grace is used
    if (std.healthy(req.backend_hint)) {
        set req.grace = /* {{ grace_period }} */s;
    }
    
    # Purge logic to remove objects from the cache
    # Tailored to Magento's cache invalidation mechanism
    # The X-Magento-Tags-Pattern value is matched to the tags in the X-Magento-Tags header
    # If X-Magento-Tags-Pattern is not set, a URL-based purge is executed
    if (req.method == "PURGE") {
        if (client.ip !~ purge) {
            return (synth(405, "Method not allowed"));
        }

        # If the X-Magento-Tags-Pattern header is not set, just use regular URL-based purge
        if (!req.http.X-Magento-Tags-Pattern) {
            return (purge);
        }

        # Full Page Cache flush
        if (req.http.X-Magento-Tags-Pattern == ".*") {
            ban("obj.http.X-Magento-Tags ~ " + req.http.X-Magento-Tags-Pattern);
        } elseif (req.http.X-Magento-Tags-Pattern) {
            # replace "((^|,)cat_c(,|$))|((^|,)cat_p(,|$))" to be "cat_c cat_p"
            set req.http.X-Magento-Tags-Pattern = regsuball(req.http.X-Magento-Tags-Pattern, "[^a-zA-Z0-9_-]+" ," ");
            set req.http.X-Magento-Tags-Pattern = regsuball(req.http.X-Magento-Tags-Pattern, "(^\s*)|(\s*$)" ,"");
            set req.http.n-gone = xkey.softpurge(req.http.X-Magento-Tags-Pattern);
            return (synth(200, "Invalidated " + req.http.n-gone + " objects"));
        }

        return (synth(200, "Purged"));
    }

    if (req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "PATCH" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "DELETE") {
          return (pipe);
    }

    # We only deal with GET and HEAD by default
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Bypass health check requests
    if (req.url ~ "^/(pub/)?(health_check.php)$") {
        return (pass);
    }

    # Collapse multiple cookie headers into one
    std.collect(req.http.Cookie, ";");

    # Remove all marketing get parameters to minimize the cache objects
    if (req.url ~ "(\?|&)(_branch_match_id|srsltid|_bta_c|_bta_tid|_ga|_gl|_ke|_kx|campid|cof|customid|cx|dclid|dm_i|ef_id|epik|fbclid|gad_source|gbraid|gclid|gclsrc|gdffi|gdfms|gdftrk|hsa_acc|hsa_ad|hsa_cam|hsa_grp|hsa_kw|hsa_mt|hsa_net|hsa_src|hsa_tgt|hsa_ver|ie|igshid|irclickid|matomo_campaign|matomo_cid|matomo_content|matomo_group|matomo_keyword|matomo_medium|matomo_placement|matomo_source|mc_cid|mc_eid|mkcid|mkevt|mkrid|mkwid|msclkid|mtm_campaign|mtm_cid|mtm_content|mtm_group|mtm_keyword|mtm_medium|mtm_placement|mtm_source|nb_klid|ndclid|origin|pcrid|piwik_campaign|piwik_keyword|piwik_kwd|pk_campaign|pk_keyword|pk_kwd|redirect_log_mongo_id|redirect_mongo_id|rtid|sb_referer_host|ScCid|si|siteurl|s_kwcid|sms_click|sms_source|sms_uph|toolid|trk_contact|trk_module|trk_msg|trk_sid|ttclid|twclid|utm_campaign|utm_content|utm_creative_format|utm_id|utm_marketing_tactic|utm_medium|utm_source|utm_source_platform|utm_term|wbraid|yclid|zanpid|mc_[a-z]+|utm_[a-z]+|_bta_[a-z]+)=") {
        set req.url = regsuball(req.url, "(_branch_match_id|srsltid|_bta_c|_bta_tid|_ga|_gl|_ke|_kx|campid|cof|customid|cx|dclid|dm_i|ef_id|epik|fbclid|gad_source|gbraid|gclid|gclsrc|gdffi|gdfms|gdftrk|hsa_acc|hsa_ad|hsa_cam|hsa_grp|hsa_kw|hsa_mt|hsa_net|hsa_src|hsa_tgt|hsa_ver|ie|igshid|irclickid|matomo_campaign|matomo_cid|matomo_content|matomo_group|matomo_keyword|matomo_medium|matomo_placement|matomo_source|mc_cid|mc_eid|mkcid|mkevt|mkrid|mkwid|msclkid|mtm_campaign|mtm_cid|mtm_content|mtm_group|mtm_keyword|mtm_medium|mtm_placement|mtm_source|nb_klid|ndclid|origin|pcrid|piwik_campaign|piwik_keyword|piwik_kwd|pk_campaign|pk_keyword|pk_kwd|redirect_log_mongo_id|redirect_mongo_id|rtid|sb_referer_host|ScCid|si|siteurl|s_kwcid|sms_click|sms_source|sms_uph|toolid|trk_contact|trk_module|trk_msg|trk_sid|ttclid|twclid|utm_campaign|utm_content|utm_creative_format|utm_id|utm_marketing_tactic|utm_medium|utm_source|utm_source_platform|utm_term|wbraid|yclid|zanpid|mc_[a-z]+|utm_[a-z]+|_bta_[a-z]+)=[-_A-z0-9+(){}%.]+&?", "");
        set req.url = regsub(req.url, "[?|&]+$", "");
    }

    # Static files caching
    if (req.url ~ "^/(pub/)?(media|static)/") {
        # Static files should not be cached by default
        return (pass);

        # But if you use a few locales and don't use CDN you can enable caching static files by commenting previous line (#return (pass);) and uncommenting next 3 lines
        #unset req.http.Https;
        #unset req.http./* {{ ssl_offloaded_header }} */;
        #unset req.http.Cookie;
    }

    # Don't cache the authenticated GraphQL requests
    if (req.url ~ "/graphql" && req.http.Authorization ~ "^Bearer") {
        return (pass);
    }

    return (hash);
}

sub vcl_hash {
    if (req.url !~ "/graphql" && req.http.cookie ~ "X-Magento-Vary=") {
        hash_data(regsub(req.http.cookie, "^.*?X-Magento-Vary=([^;]+);*.*$", "\1"));
    }

    # To make sure http users don't see ssl warning
    hash_data(req.http./* {{ ssl_offloaded_header }} */);
    
    # To make sure http users don't see ssl warning
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }

    /* {{ design_exceptions_code }} */

    if (req.url ~ "/graphql") {
        if (req.http.X-Magento-Cache-Id) {
            hash_data(req.http.X-Magento-Cache-Id);
        } else {
            # if no X-Magento-Cache-Id (which already contains Store & Currency) is not set, use the HTTP headers
            hash_data(req.http.Store);
            hash_data(req.http.Content-Currency);
        }

        # When the frontend stops sending the auth token, make sure users stop getting results cached for logged-in users
        if (req.http.Authorization ~ "^Bearer") {
            hash_data("Authorized");
        }
    }
}

sub vcl_backend_response {
    # Serve stale content for three days after object expiration
    # Perform asynchronous revalidation while stale content is served
    set beresp.grace = 1d;
    
    if (beresp.http.X-Magento-Tags) {
        # set comma separated xkey with "all" tag
        set beresp.http.XKey = beresp.http.X-Magento-Tags + ",all";
        # remove X-Magento-Tags, no longer needed
        unset beresp.http.X-Magento-Tags;
    }

    # All text-based content can be parsed as ESI
    if (beresp.http.content-type ~ "text") {
        set beresp.do_esi = true;
    }

    # Only cache HTTP 200 and HTTP 404 responses
    if (beresp.status != 200 && beresp.status != 404) {
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
        return (deliver);
    }
    
    # Don't cache if the request cache ID doesn't match the response cache ID for graphql requests
    if (bereq.url ~ "/graphql" && bereq.http.X-Magento-Cache-Id && bereq.http.X-Magento-Cache-Id != beresp.http.X-Magento-Cache-Id) {
       set beresp.ttl = 120s;
       set beresp.uncacheable = true;
       return (deliver);
    }

    # Remove the Set-Cookie header for cacheable content
    # Only for HTTP GET & HTTP HEAD requests
    if (beresp.ttl > 0s && (bereq.method == "GET" || bereq.method == "HEAD")) {
        unset beresp.http.Set-Cookie;
    }
    
   # If page is not cacheable then bypass varnish for 2 minutes as Hit-for-Miss
   if (beresp.ttl <= 0s ||
        beresp.http.Surrogate-control ~ "no-store" ||
        (!beresp.http.Surrogate-Control && beresp.http.Vary == "*")) {
        # Mark as Hit-for-Miss for the next 2 minutes
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
    }
}

sub vcl_deliver {
    if (obj.uncacheable) {
        set resp.http.X-Magento-Cache-Debug = "UNCACHEABLE";
    } else if (obj.hits) {
        set resp.http.X-Magento-Cache-Debug = "HIT";
        set resp.http.Grace = req.http.grace;
    } else {
        set resp.http.X-Magento-Cache-Debug = "MISS";
    }

    # Let browser and Cloudflare cache non-static content that are cacheable for short period of time
    if (resp.http.Cache-Control !~ "private" && req.url !~ "^/(pub/)?(media|static)/" && obj.ttl > 0s) {
        set resp.http.Cache-Control = "must-revalidate, max-age=60";
    }

    unset resp.http.XKey;
    unset resp.http.Expires;
    unset resp.http.Pragma;
    unset resp.http.X-Magento-Debug;
    unset resp.http.X-Magento-Tags;
    unset resp.http.X-Powered-By;
    unset resp.http.Server;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    unset resp.http.Link;
}
