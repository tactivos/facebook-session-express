FACEBOOK_COOKIE_PREFIX = 'fbsr_';

var crypto = require('crypto');

module.exports = function(app, secret) {
	return function(req, res, next) {
		var cookie = req.cookies[FACEBOOK_COOKIE_PREFIX + app];

		if(cookie) {
			var chunks = cookie.split('.', 2);

			var rawSignature = chunks[0].replace(/\-/g, '+').replace(/\_/g, '/');
			var hexSignature = new Buffer(rawSignature, 'base64').toString('hex');

	        var rawToken = new Buffer(chunks[1].replace(/\-/g, '+').replace(/\_/g, '/'), 'base64').toString();
	        var token = JSON.parse(rawToken);

	        var hmac = crypto.createHmac('sha256', secret);
        	hmac.update(chunks[1]);

        	var expectedSignature = hmac.digest('hex');

        	if(expectedSignature == hexSignature) {
        		req.facebook = {session: token};
        	}
		}
		
		next();
	}
}
