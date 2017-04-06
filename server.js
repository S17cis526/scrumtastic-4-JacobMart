"use strict";

var PORT = 3040;

var http = require('http');
var fileserver = require('./lib/fileserver');
var sqlite3 = require('sqlite3').verbose();
var db = new sqlite3.Database('scrumtastic.sqlite3', function(err) {
  if(err) console.error(err);
});
var router = new (require('./lib/route')).Router(db);

// Cache static directory in the fileserver
fileserver.loadDir('public');

// Define our routes
var project = require('./src/resource/project');
router.resource('/projects', project);

var server = new http.Server(function(req, res) {
  // Remove the leading '/' from the resource url
  var resource = req.url.slice(1);
  // If no resource is requested, serve the cached index page.
  if(resource == '')
    fileserver.serveFile('public/index.html', req, res);
  // If the resource is cached in the fileserver, serve it
  else if(fileserver.isCached(resource))
    fileserver.serveFile(resource, req, res);
  // Otherwise, route the request
  else router.route(req, res);
});

// Launch the server
server.listen(PORT, function(){
  console.log("listening on port " + PORT);
});
