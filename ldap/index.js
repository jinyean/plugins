'use strict';
var debug = require('debug')('plugin:ldap');
var ldap = require('ldapjs');

function sendError(res) {
	var errorInfo = {
		"code": "403",
		"message": "LDAP failed"
	};
	res.writeHead(403, { 'Content-Type': 'application/json' });
	res.write(JSON.stringify(errorInfo));
	res.end();
}

module.exports.init = function(config, logger, stats) {

  return {
    onrequest: function(req, res, next) {

      var ldapurl = 'ldap://'+config.host+':'+config.port;

      var client = ldap.createClient({
        url: ldapurl
      });

      var auth=req.headers['authorization'];

      console.log(auth);

      var tmp = auth.split(' ');
      var buf = new Buffer(tmp[1], 'base64');
      var plain_auth = buf.toString();

      var creds = plain_auth.split(':');
      var username = creds[0];
      var password = creds[1].trim();

      console.log(username);
      console.log(password);

      var dn='cn='+username+','+config.base;

      client.bind(dn, password, function(err) {
        if (err) {
           sendError(res);
        } else {
           console.log("Bind Successfull");
           next();
        }
      });

   }
  };
}
