/** @module sessions
 * a module representing a user sessions
*/

module.exports = {
  create: create,
  destroy: destroy,
  loginRequired: loginRequired
};

var json = require('../../lib/form-json');
var encryption = require('../../lib/encryption');

/** @function create
 * creates a new session
 */
function create(req, res, db){
  json(req, res, function(req,res){
    var username = req.body.username;
    var password = req.body.password;
    db.get("SELECT * FROM users WHERE username=?", [username], function(err, user){
      if(err){
        res.statusCode = 500;
      res.end("Server error");
      return;
    }
    if(!user){
      //username not in database
      res.statusCode = 403;
      res.end("Incorrect username/password")
      return;
    }
    var cryptedPassword = encryption.digest(password + user.salt);
    if(cryptedPassword != user.cryptedPassword){
      //invalid password/username combo
      res.statusCode = 403;
      res.end("Incorrect username/password");
      return;
    }
    else{
      //successful login!
      //store user.id in the cookie
      var cookieData= JSON.stringify({userId: user.id});
      var encryptedCookieData = encryption.encipher(cookieData);
      //Encrypted userid
      res.setHeader("Set-Cookie", ["session=" + encryptedCookieData]);
      res.statusCode = 200;
      res.end("Successful Login");
    }
    });

  });
}


function destroy(req, res){
  res.setHeader("Set-Cookie", "");
  res.statusCode = 200;
  res.end("Logged out successfully");
}

function loginRequired(req, res, next) {
  var session = req.headers.cookie.session;
  var sessionData = encryption.decipher(session);
  var sessionObj = JSON.parse(sessionData);
  if(sessionObj.userId){
    req.currentUserId = sessionObj.userId;
    return next(req, res);
  }
}
