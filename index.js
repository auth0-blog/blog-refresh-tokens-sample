var express = require('express');
var bodyParser = require('body-parser');
var oauthserver = require('oauth2-server');
var mongoose = require('mongoose');
var model = require('./model');

var mongoUrl = process.env.MONGO_URL || 'mongodb://localhost/test';

mongoose.connect(mongoUrl, function (err, res) {
  if (err) {
    console.log('ERROR connecting to: ' + mongoUrl + '. ' + err);
  } else {
    console.log('Succeeded connecting to: ' + mongoUrl);
  }
});

var app = express();

app.use(bodyParser.urlencoded({ extended: true }));

app.use(bodyParser.json());

app.oauth = oauthserver({
  model: model,
  grants: ['auth_code', 'password', 'refresh_token'],
  debug: true,
  accessTokenLifetime: model.accessTokenLifetime
});

// Handle token grant requests
app.all('/oauth/token', app.oauth.grant());

app.get('/secret', app.oauth.authorise(), function (req, res) {
  // Will require a valid access_token
  res.send('Secret area');
});

app.get('/public', function (req, res) {
  // Does not require an access_token
  res.send('Public area');
});

// Error handling
app.use(app.oauth.errorHandler());

app.listen(3000);

